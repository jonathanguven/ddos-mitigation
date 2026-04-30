#!/usr/bin/env python3
"""Ryu OpenFlow 1.3 learning switch with IDS detection and mitigation."""

import json
import os
import time
from collections import defaultdict, deque
from pathlib import Path

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, ipv4, packet
from ryu.ofproto import ofproto_v1_3


MONITOR_INTERVAL = 2

SINGLE_SOURCE_DROP_THRESHOLD = 5000
MULTI_SOURCE_MIN_RATE = 300
MULTI_SOURCE_SOURCE_COUNT = 3
METER_RATE_KBPS = 1000
METER_BURST_SIZE = 100

STATS_FILE = Path("/tmp/sdn_ids_stats.json")
ALERTS_FILE = Path("/tmp/sdn_ids_alerts.json")
STATE_FILE = Path("/tmp/sdn_ids_state.json")
RESET_FILE = Path("/tmp/sdn_ids_reset.signal")

HOSTS = {
    "10.0.0.1": {"host": "h1", "role": "normal"},
    "10.0.0.2": {"host": "h2", "role": "normal"},
    "10.0.0.3": {"host": "h3", "role": "normal"},
    "10.0.0.4": {"host": "h4", "role": "normal"},
    "10.0.0.5": {"host": "h5", "role": "normal"},
}


class IdsController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.datapaths = {}
        self.flow_stats = {}
        self.mitigated = {}
        self.meter_ids = {}
        self.next_meter_id = 1
        self.installed_meters = set()
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
                "mitigation": None,
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
        self.ip_to_mac.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.ip_to_mac[dpid][ip_pkt.src] = src
            self.ip_to_mac[dpid][ip_pkt.dst] = dst

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
        total_packet_rate = 0
        total_byte_rate = 0
        victim_rates = defaultdict(lambda: {"packet_rate": 0, "byte_rate": 0})
        victim_sources = defaultdict(set)
        for stat in ev.msg.body:
            match = self._match_to_dict(stat.match)
            src_ip = match.get("ipv4_src")
            dst_ip = match.get("ipv4_dst")
            if not src_ip or not dst_ip:
                continue

            flow_key = (datapath.id, src_ip, dst_ip, stat.priority)
            previous = self.flow_stats.get(flow_key)
            flow_record = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "prev_packets": previous["curr_packets"] if previous else stat.packet_count,
                "curr_packets": stat.packet_count,
                "packet_rate": 0,
                "prev_bytes": previous["curr_bytes"] if previous else stat.byte_count,
                "curr_bytes": stat.byte_count,
                "byte_rate": 0,
                "last_seen": now,
                "priority": stat.priority,
            }
            self.flow_stats[flow_key] = flow_record
            if not previous:
                continue

            elapsed = max(now - previous["last_seen"], 0.001)
            packet_rate = max((stat.packet_count - previous["curr_packets"]) / elapsed, 0)
            byte_rate = max((stat.byte_count - previous["curr_bytes"]) / elapsed, 0)
            is_drop = self._is_drop_stat(stat)
            is_meter = self._has_meter_instruction(stat)

            flow_record.update(packet_rate=packet_rate, byte_rate=byte_rate)
            total_packet_rate += packet_rate
            total_byte_rate += byte_rate

            if src_ip in host_updates:
                source = host_updates[src_ip]
                source["packet_rate"] += round(packet_rate)
                source["byte_rate"] += round(byte_rate)
                mitigation = self.mitigated.get((src_ip, dst_ip))
                if is_drop or (mitigation and mitigation["action"] == "drop"):
                    source["status"] = "blocked"
                    source["mitigation"] = "drop"
                    source["role"] = "attacker"
                elif is_meter or (mitigation and mitigation["action"] == "rate_limit"):
                    source["status"] = "rate_limited"
                    source["mitigation"] = "rate_limit"
                    if source["role"] in {"host", "normal"}:
                        source["role"] = "suspicious"
                else:
                    source["status"] = "active"

            if not is_drop:
                victim_rates[dst_ip]["packet_rate"] += packet_rate
                victim_rates[dst_ip]["byte_rate"] += byte_rate
                if packet_rate >= MULTI_SOURCE_MIN_RATE:
                    victim_sources[dst_ip].add(src_ip)

            self._evaluate_single_source(datapath, src_ip, dst_ip, packet_rate)

        self._evaluate_multi_source_flood(datapath, victim_sources)

        for dst_ip, rates in victim_rates.items():
            if dst_ip not in host_updates:
                continue
            victim = host_updates[dst_ip]
            is_multi_source_victim = len(victim_sources[dst_ip]) >= MULTI_SOURCE_SOURCE_COUNT
            is_high_rate_victim = rates["packet_rate"] >= SINGLE_SOURCE_DROP_THRESHOLD
            victim["packet_rate"] = round(rates["packet_rate"])
            victim["byte_rate"] = round(rates["byte_rate"])
            victim["status"] = (
                "under_attack" if is_multi_source_victim or is_high_rate_victim else "receiving"
            )
            if victim["status"] == "under_attack":
                victim["role"] = "victim"

        self._apply_mitigation_to_hosts(host_updates)

        self.host_stats = host_updates
        if any(item["action"] == "drop" for item in self.mitigated.values()):
            self.demo_state = "mitigated"
        elif any(item["action"] == "rate_limit" for item in self.mitigated.values()):
            self.demo_state = "rate_limited"
        elif any(
            rates["packet_rate"] >= SINGLE_SOURCE_DROP_THRESHOLD
            or len(victim_sources[dst_ip]) >= MULTI_SOURCE_SOURCE_COUNT
            for dst_ip, rates in victim_rates.items()
        ):
            self.demo_state = "attack"
        elif total_packet_rate > 0:
            self.demo_state = "normal"
        elif self.demo_state in {"normal", "attack", "rate_limited"}:
            self.demo_state = "idle"
        self.metrics.append(
            {
                "time": time.strftime("%H:%M:%S"),
                "packet_rate": round(total_packet_rate),
                "byte_rate": round(total_byte_rate),
                "victim_throughput": round(
                    sum(rates["byte_rate"] for rates in victim_rates.values())
                ),
            }
        )
        self._write_all_state()

    def _evaluate_single_source(self, datapath, src_ip, dst_ip, packet_rate):
        key = (src_ip, dst_ip)
        mitigation = self.mitigated.get(key)
        if packet_rate >= SINGLE_SOURCE_DROP_THRESHOLD:
            if not mitigation or mitigation["action"] != "drop":
                self.install_drop_rule(datapath, src_ip, dst_ip)
                self.mitigated[key] = {
                    "action": "drop",
                    "type": "single_source_flood",
                    "installed_at": time.time(),
                }
                self._add_alert(
                    "critical",
                    (
                        f"High-rate flood detected from {src_ip} to {dst_ip}. "
                        f"Drop rule installed on s{datapath.id}."
                    ),
                    alert_type="single_source_flood",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    mitigation="drop",
                )
            return

    def _evaluate_multi_source_flood(self, datapath, victim_sources):
        for dst_ip, sources in victim_sources.items():
            if len(sources) < MULTI_SOURCE_SOURCE_COUNT:
                continue
            installed_sources = []
            for src_ip in sorted(sources):
                key = (src_ip, dst_ip)
                existing_action = self.mitigated.get(key, {}).get("action")
                if existing_action in {"drop", "rate_limit"}:
                    continue
                if self.install_meter_rule(datapath, src_ip, dst_ip):
                    self.mitigated[key] = {
                        "action": "rate_limit",
                        "type": "multi_source_flood",
                        "installed_at": time.time(),
                    }
                    installed_sources.append(src_ip)

            if installed_sources:
                self._add_alert(
                    "warning",
                    (
                        f"Multiple sources are targeting {dst_ip}. "
                        "Rate limiting applied."
                    ),
                    alert_type="multi_source_flood",
                    src_ips=sorted(sources),
                    dst_ip=dst_ip,
                    mitigation="rate_limit",
                )

    def install_drop_rule(self, datapath, src_ip, dst_ip):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
        )
        self.add_flow(datapath, 100, match, [], idle_timeout=30, hard_timeout=60)

    def get_or_create_meter_id(self, src_ip, dst_ip):
        key = (src_ip, dst_ip)
        if key not in self.meter_ids:
            self.meter_ids[key] = self.next_meter_id
            self.next_meter_id += 1
        return self.meter_ids[key]

    def install_meter(self, datapath, meter_id, rate_kbps=METER_RATE_KBPS):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        bands = [
            parser.OFPMeterBandDrop(
                rate=rate_kbps,
                burst_size=METER_BURST_SIZE,
            )
        ]
        req = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands,
        )
        datapath.send_msg(req)

    def install_meter_rule(self, datapath, src_ip, dst_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dst_mac = self.ip_to_mac.get(datapath.id, {}).get(dst_ip)
        out_port = None
        if dst_mac:
            out_port = self.mac_to_port.get(datapath.id, {}).get(dst_mac)
        if not out_port or out_port == ofproto.OFPP_FLOOD:
            return False

        meter_id = self.get_or_create_meter_id(src_ip, dst_ip)
        meter_key = (datapath.id, meter_id)
        if meter_key not in self.installed_meters:
            self.install_meter(datapath, meter_id, METER_RATE_KBPS)
            self.installed_meters.add(meter_key)

        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
        )
        actions = [parser.OFPActionOutput(out_port)]
        instructions = [
            parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER),
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=90,
            match=match,
            instructions=instructions,
            idle_timeout=30,
            hard_timeout=60,
        )
        datapath.send_msg(mod)
        return True

    def _handle_reset_signal(self):
        try:
            reset_mtime = RESET_FILE.stat().st_mtime
        except OSError:
            return

        if reset_mtime <= self.last_reset_signal:
            return

        self.last_reset_signal = reset_mtime
        self._remove_mitigation_flows()
        self.flow_stats.clear()
        self.mitigated.clear()
        self.meter_ids.clear()
        self.installed_meters.clear()
        self.next_meter_id = 1
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
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match,
            )
            datapath.send_msg(mod)
            meter_mod = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_DELETE,
                flags=0,
                meter_id=ofproto.OFPM_ALL,
                bands=[],
            )
            datapath.send_msg(meter_mod)

    def _expire_mitigation_state(self):
        now = time.time()
        expired = [
            key
            for key, mitigation in self.mitigated.items()
            if now - mitigation["installed_at"] > 65
        ]
        for key in expired:
            self.mitigated.pop(key, None)

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

    def _has_meter_instruction(self, stat):
        for instruction in getattr(stat, "instructions", []):
            if instruction.__class__.__name__ == "OFPInstructionMeter":
                return True
            if getattr(instruction, "meter_id", None) is not None:
                return True
        return False

    def _apply_mitigation_to_hosts(self, host_updates):
        for (src_ip, dst_ip), mitigation in self.mitigated.items():
            if src_ip in host_updates:
                host = host_updates[src_ip]
                host["mitigation"] = mitigation["action"]
                if mitigation["action"] == "drop":
                    host["status"] = "blocked"
                    host["role"] = "attacker"
                elif host["status"] != "blocked":
                    host["status"] = "rate_limited"
                    if host["role"] in {"host", "normal"}:
                        host["role"] = "suspicious"
            if dst_ip in host_updates and host_updates[dst_ip]["status"] == "idle":
                host_updates[dst_ip]["status"] = "protected"
                host_updates[dst_ip]["role"] = "victim"
            elif dst_ip in host_updates and host_updates[dst_ip]["status"] == "under_attack":
                host_updates[dst_ip]["role"] = "victim"

    def _add_alert(self, level, message, **fields):
        alert = {
            "time": time.strftime("%H:%M:%S"),
            "level": level,
            "message": message,
            **fields,
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
