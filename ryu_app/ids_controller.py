#!/usr/bin/env python3
"""Ryu OpenFlow 1.3 learning switch with simple DDoS detection and mitigation."""

import json
import os
import time
from collections import deque
from pathlib import Path

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, ipv4, packet
from ryu.ofproto import ofproto_v1_3


PACKET_RATE_THRESHOLD = 1000
MONITOR_INTERVAL = 2
ATTACKER_IP = "10.0.0.1"
VICTIM_IP = "10.0.0.5"
STATS_FILE = Path("/tmp/sdn_ids_stats.json")
ALERTS_FILE = Path("/tmp/sdn_ids_alerts.json")
STATE_FILE = Path("/tmp/sdn_ids_state.json")
RESET_FILE = Path("/tmp/sdn_ids_reset.signal")

HOSTS = {
    "10.0.0.1": {"host": "h1", "role": "attacker"},
    "10.0.0.2": {"host": "h2", "role": "normal"},
    "10.0.0.3": {"host": "h3", "role": "normal"},
    "10.0.0.4": {"host": "h4", "role": "normal"},
    "10.0.0.5": {"host": "h5", "role": "victim"},
}


class IdsController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_counters = {}
        self.mitigated = {}
        self.last_reset_signal = 0
        self.demo_state = "idle"
        self.alerts = deque(maxlen=100)
        self.metrics = deque(maxlen=120)
        self.host_stats = self._initial_host_stats()
        self.monitor_thread = hub.spawn(self._monitor)
        self._write_all_state()

    def _initial_host_stats(self):
        return {
            ip: {
                "host": meta["host"],
                "ip": ip,
                "role": meta["role"],
                "packet_rate": 0,
                "byte_rate": 0,
                "status": "idle",
            }
            for ip, meta in HOSTS.items()
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self._add_alert("info", f"Switch s{datapath.id} connected to IDS controller")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
        self._write_all_state()

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if out_port != ofproto.OFPP_FLOOD:
            if ip_pkt:
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                )
                self.add_flow(datapath, 10, match, actions, idle_timeout=30, hard_timeout=90)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions, idle_timeout=30, hard_timeout=90)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def _monitor(self):
        while True:
            self._handle_reset_signal()
            self._expire_mitigation_state()
            for datapath in list(self.datapaths.values()):
                self._request_stats(datapath)
            self._write_all_state()
            hub.sleep(MONITOR_INTERVAL)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        now = time.time()
        host_updates = self._initial_host_stats()
        victim_packet_rate = 0
        victim_byte_rate = 0
        total_packet_rate = 0
        total_byte_rate = 0

        for stat in ev.msg.body:
            match = self._match_to_dict(stat.match)
            src_ip = match.get("ipv4_src")
            dst_ip = match.get("ipv4_dst")
            if not src_ip or not dst_ip:
                continue

            key = (datapath.id, src_ip, dst_ip, stat.priority)
            previous = self.flow_counters.get(key)
            self.flow_counters[key] = (stat.packet_count, stat.byte_count, now)
            if not previous:
                continue

            prev_packets, prev_bytes, prev_time = previous
            elapsed = max(now - prev_time, 0.001)
            packet_rate = max((stat.packet_count - prev_packets) / elapsed, 0)
            byte_rate = max((stat.byte_count - prev_bytes) / elapsed, 0)
            is_drop = self._is_drop_stat(stat)

            total_packet_rate += packet_rate
            total_byte_rate += byte_rate

            if src_ip in host_updates:
                source = host_updates[src_ip]
                source["packet_rate"] += round(packet_rate)
                source["byte_rate"] += round(byte_rate)
                source["status"] = "blocked" if is_drop else "active"

            if dst_ip == VICTIM_IP and not is_drop:
                victim_packet_rate += packet_rate
                victim_byte_rate += byte_rate

            if (
                src_ip == ATTACKER_IP
                and dst_ip == VICTIM_IP
                and packet_rate > PACKET_RATE_THRESHOLD
                and src_ip not in self.mitigated
            ):
                self._add_alert("warning", "High packet rate detected from h1")
                self._add_alert("warning", "DDoS suspected against h5")
                self._install_mitigation(datapath, src_ip, dst_ip)

        if victim_packet_rate > 0 and VICTIM_IP in host_updates:
            victim = host_updates[VICTIM_IP]
            victim["packet_rate"] = round(victim_packet_rate)
            victim["byte_rate"] = round(victim_byte_rate)
            victim["status"] = (
                "under_attack"
                if victim_packet_rate > PACKET_RATE_THRESHOLD
                else "receiving"
            )

        if ATTACKER_IP in self.mitigated:
            host_updates[ATTACKER_IP]["status"] = "blocked"
            if VICTIM_IP in host_updates and host_updates[VICTIM_IP]["packet_rate"] == 0:
                host_updates[VICTIM_IP]["status"] = "protected"

        self.host_stats = host_updates
        if ATTACKER_IP not in self.mitigated:
            if victim_packet_rate > PACKET_RATE_THRESHOLD:
                self.demo_state = "attack"
            elif total_packet_rate > 0:
                self.demo_state = "normal"
            elif self.demo_state in {"normal", "attack"}:
                self.demo_state = "idle"
        self.metrics.append(
            {
                "time": time.strftime("%H:%M:%S"),
                "packet_rate": round(total_packet_rate),
                "byte_rate": round(total_byte_rate),
                "victim_throughput": round(victim_byte_rate),
            }
        )
        self._write_all_state()

    def _install_mitigation(self, datapath, src_ip, dst_ip):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
        )
        self.add_flow(datapath, 100, match, [], idle_timeout=30, hard_timeout=60)
        self.mitigated[src_ip] = time.time()
        self.demo_state = "mitigated"
        self._add_alert(
            "critical",
            f"DDoS detected from {src_ip} to {dst_ip}. Drop rule installed on s{datapath.id}.",
        )

    def _handle_reset_signal(self):
        try:
            reset_mtime = RESET_FILE.stat().st_mtime
        except OSError:
            return

        if reset_mtime <= self.last_reset_signal:
            return

        self.last_reset_signal = reset_mtime
        self._remove_mitigation_flows()
        self.flow_counters.clear()
        self.mitigated.clear()
        self.demo_state = "idle"
        self.host_stats = self._initial_host_stats()
        self.metrics.clear()
        self.alerts.clear()
        self.alerts.append(
            {
                "time": time.strftime("%H:%M:%S"),
                "level": "info",
                "message": "Demo reset",
            }
        )
        self._write_all_state()

    def _remove_mitigation_flows(self):
        for datapath in list(self.datapaths.values()):
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ATTACKER_IP,
                ipv4_dst=VICTIM_IP,
            )
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=100,
                match=match,
            )
            datapath.send_msg(mod)

    def _expire_mitigation_state(self):
        now = time.time()
        expired = [
            src_ip
            for src_ip, installed_at in self.mitigated.items()
            if now - installed_at > 65
        ]
        for src_ip in expired:
            self.mitigated.pop(src_ip, None)

    def _match_to_dict(self, match):
        try:
            return dict(match.items())
        except Exception:
            return {}

    def _is_drop_stat(self, stat):
        for instruction in getattr(stat, "instructions", []):
            actions = getattr(instruction, "actions", None)
            if actions:
                return False
        return stat.priority >= 100

    def _add_alert(self, level, message):
        alert = {
            "time": time.strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        }
        if not self.alerts or self.alerts[-1]["message"] != message:
            self.alerts.append(alert)
        if level == "critical":
            self.demo_state = "mitigated"
        self._write_all_state()

    def _write_all_state(self):
        self._atomic_write(
            STATS_FILE,
            {
                "hosts": list(self.host_stats.values()),
                "history": list(self.metrics),
                "last_updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
        )
        self._atomic_write(ALERTS_FILE, {"alerts": list(self.alerts)})
        self._atomic_write(
            STATE_FILE,
            {
                "demo_state": self.demo_state,
                "ryu_running": True,
                "mininet_running": bool(self.datapaths),
                "last_updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
        )

    def _atomic_write(self, path, payload):
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        os.replace(tmp_path, path)
