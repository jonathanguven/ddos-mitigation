#!/usr/bin/env python3
"""Ryu OpenFlow 1.3 learning switch with IDS detection and mitigation."""

import time
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, ipv4, packet
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.ofproto import ofproto_v1_3
from webob import Response


MONITOR_INTERVAL = 0.5

SINGLE_SOURCE_DROP_THRESHOLD = 5000
MULTI_SOURCE_MIN_RATE = 300
MULTI_SOURCE_SOURCE_COUNT = 3
METER_RATE_KBPS = 1000
METER_BURST_SIZE = 100

IDS_INSTANCE_NAME = "ids_controller_app"

HOSTS = {
    "10.0.0.1": {"host": "h1", "role": "normal"},
    "10.0.0.2": {"host": "h2", "role": "normal"},
    "10.0.0.3": {"host": "h3", "role": "normal"},
    "10.0.0.4": {"host": "h4", "role": "normal"},
    "10.0.0.5": {"host": "h5", "role": "normal"},
}


def current_clock_ms():
    return f"{time.strftime('%H:%M:%S')}.{int((time.time() % 1) * 1000):03d}"


def current_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def json_response(payload, status=200):
    import json

    return Response(
        content_type="application/json",
        status=status,
        body=json.dumps(payload).encode("utf-8"),
    )


class IdsController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.datapaths = {}
        self.flow_stats = {}
        self.latest_flows = {}
        self.mitigated = {}
        self.meter_ids = {}
        self.meter_configs = {}
        self.meter_stats = {}
        self.next_meter_id = 1
        self.installed_meters = set()
        self.demo_state = "idle"
        self.alerts = deque(maxlen=100)
        self.metrics = deque(maxlen=120)
        self.host_stats = self._initial_host_stats()
        self.last_updated = current_iso()
        wsgi.register(IdsRestController, {IDS_INSTANCE_NAME: self})
        self.monitor_thread = hub.spawn(self._monitor)

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
        self.install_table_miss(datapath)
        self._add_alert("info", f"Switch s{datapath.id} connected to IDS controller")

    def install_table_miss(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self.latest_flows = {
                key: flow
                for key, flow in self.latest_flows.items()
                if key[0] != datapath.id
            }
        self._touch()

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
            self._expire_mitigation_state()
            for datapath in list(self.datapaths.values()):
                self._request_stats(datapath)
                self._request_meter_stats(datapath)
            self._touch()
            hub.sleep(MONITOR_INTERVAL)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _request_meter_stats(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        try:
            req = parser.OFPMeterStatsRequest(datapath, 0, ofproto.OFPM_ALL)
        except TypeError:
            req = parser.OFPMeterStatsRequest(datapath, meter_id=ofproto.OFPM_ALL)
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
        latest_flow_keys = set()
        for stat in ev.msg.body:
            flow = self._serialize_flow_stat(datapath.id, stat)
            if not self._is_table_miss_flow(flow):
                flow_key_for_table = (datapath.id, flow["priority"], flow["match"], flow["actions"])
                self.latest_flows[flow_key_for_table] = flow
                latest_flow_keys.add(flow_key_for_table)

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
                "time": current_clock_ms(),
                "packet_rate": round(total_packet_rate),
                "byte_rate": round(total_byte_rate),
                "victim_throughput": round(
                    sum(rates["byte_rate"] for rates in victim_rates.values())
                ),
            }
        )
        self.latest_flows = {
            key: flow
            for key, flow in self.latest_flows.items()
            if key[0] != datapath.id or key in latest_flow_keys
        }
        self._touch()

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        for stat in ev.msg.body:
            meter_id = getattr(stat, "meter_id", None)
            if meter_id is None:
                continue
            self.meter_stats[(datapath.id, meter_id)] = {
                "packet_count": int(getattr(stat, "packet_in_count", 0) or 0),
                "byte_count": int(getattr(stat, "byte_in_count", 0) or 0),
            }
        self._touch()

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
            self.meter_configs[meter_key] = {
                "meter_id": meter_id,
                "rate_kbps": METER_RATE_KBPS,
                "burst_size": METER_BURST_SIZE,
            }

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

    def reset_controller_state(self):
        self._reset_switch_state()
        self.mac_to_port.clear()
        self.ip_to_mac.clear()
        self.flow_stats.clear()
        self.latest_flows.clear()
        self.mitigated.clear()
        self.meter_ids.clear()
        self.meter_configs.clear()
        self.meter_stats.clear()
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
        self._touch()
        return {"ok": True, "message": "Ryu controller state reset"}

    def _reset_switch_state(self):
        for datapath in list(self.datapaths.values()):
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            match = parser.OFPMatch()
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
            self.install_table_miss(datapath)

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
        self._touch()

    def _touch(self):
        self.last_updated = current_iso()

    def get_status_payload(self):
        return {
            "demo_state": self.demo_state,
            "ryu_running": True,
            "mininet_running": bool(self.datapaths),
            "last_updated": self.last_updated,
        }

    def get_stats_payload(self):
        return {
            "hosts": list(self.host_stats.values()),
            "history": list(self.metrics),
            "last_updated": self.last_updated,
        }

    def get_alerts_payload(self):
        return {"alerts": list(self.alerts)[-100:]}

    def get_datapaths_payload(self):
        return {
            "datapaths": [
                {"id": dpid, "name": f"s{dpid}", "connected": True}
                for dpid in sorted(self.datapaths)
            ],
            "last_updated": self.last_updated,
        }

    def get_flows_payload(self):
        flows = sorted(
            (dict(flow) for flow in self.latest_flows.values()),
            key=lambda flow: (-flow["priority"], flow["switch"], flow["match"], flow["actions"]),
        )
        for index, flow in enumerate(flows, start=1):
            flow["table_order"] = index
            flow["raw"] = self._flow_raw(flow)
        return {"flows": flows, "raw": [flow["raw"] for flow in flows], "error": None}

    def get_meters_payload(self):
        meters = []
        for (dpid, meter_id), config in sorted(self.meter_configs.items()):
            stats = self.meter_stats.get((dpid, meter_id), {})
            meter = {
                "meter_id": int(meter_id),
                "rate_kbps": int(config.get("rate_kbps", 0) or 0),
                "burst_size": int(config.get("burst_size", 0) or 0),
                "packet_count": int(stats.get("packet_count", 0) or 0),
                "byte_count": int(stats.get("byte_count", 0) or 0),
            }
            meter["raw"] = self._meter_raw(meter)
            meters.append(meter)
        return {"meters": meters, "raw": [meter["raw"] for meter in meters], "error": None}

    def get_mitigations_payload(self):
        mitigations = []
        for (src_ip, dst_ip), mitigation in sorted(self.mitigated.items()):
            mitigations.append(
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "action": mitigation.get("action"),
                    "type": mitigation.get("type"),
                    "installed_at": mitigation.get("installed_at"),
                }
            )
        return {"mitigations": mitigations, "last_updated": self.last_updated}

    def _serialize_flow_stat(self, dpid, stat):
        match = self._match_to_dict(stat.match)
        actions = self._actions_to_string(stat)
        flow = {
            "switch": f"s{dpid}",
            "priority": int(getattr(stat, "priority", 0) or 0),
            "packets": int(getattr(stat, "packet_count", 0) or 0),
            "bytes": int(getattr(stat, "byte_count", 0) or 0),
            "match": self._match_to_string(match),
            "actions": actions,
            "meter_id": self._meter_id_from_stat(stat),
            "status": "Active",
            "raw": "",
        }
        flow["raw"] = self._flow_raw(flow)
        return flow

    def _match_to_string(self, match):
        if not match:
            return "all"
        parts = []
        if match.get("eth_type") == ether_types.ETH_TYPE_IP:
            parts.append("ip")
        for key in ("in_port", "eth_src", "eth_dst", "ipv4_src", "ipv4_dst"):
            if key in match:
                display_key = {"ipv4_src": "nw_src", "ipv4_dst": "nw_dst"}.get(key, key)
                parts.append(f"{display_key}={match[key]}")
        return ",".join(parts) if parts else ",".join(f"{key}={value}" for key, value in match.items())

    def _actions_to_string(self, stat):
        action_parts = []
        meter_id = self._meter_id_from_stat(stat)
        if meter_id is not None:
            action_parts.append(f"meter:{meter_id}")
        for instruction in getattr(stat, "instructions", []):
            for action in getattr(instruction, "actions", []) or []:
                port = getattr(action, "port", None)
                if port is not None:
                    action_parts.append(f"output:{self._port_to_string(port)}")
        return ",".join(action_parts) if action_parts else "drop"

    def _meter_id_from_stat(self, stat):
        for instruction in getattr(stat, "instructions", []):
            meter_id = getattr(instruction, "meter_id", None)
            if meter_id is not None:
                return int(meter_id)
        return None

    def _flow_raw(self, flow):
        return (
            f"priority={flow['priority']},{flow['match']},"
            f"n_packets={flow['packets']},n_bytes={flow['bytes']},"
            f"actions={flow['actions']}"
        )

    def _meter_raw(self, meter):
        return (
            f"meter={meter['meter_id']} kbps bands="
            f"type=drop rate={meter['rate_kbps']} burst_size={meter['burst_size']} "
            f"packet_in_count={meter['packet_count']} byte_in_count={meter['byte_count']}"
        )

    def _port_to_string(self, port):
        reserved_ports = {
            ofproto_v1_3.OFPP_IN_PORT: "IN_PORT",
            ofproto_v1_3.OFPP_TABLE: "TABLE",
            ofproto_v1_3.OFPP_NORMAL: "NORMAL",
            ofproto_v1_3.OFPP_FLOOD: "FLOOD",
            ofproto_v1_3.OFPP_ALL: "ALL",
            ofproto_v1_3.OFPP_CONTROLLER: "CONTROLLER",
            ofproto_v1_3.OFPP_LOCAL: "LOCAL",
            ofproto_v1_3.OFPP_ANY: "ANY",
        }
        return reserved_ports.get(port, str(port))

    def _is_table_miss_flow(self, flow):
        return (
            flow.get("priority") == 0
            and flow.get("match") == "all"
            and "CONTROLLER" in str(flow.get("actions", "")).upper()
        )


class IdsRestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.ids_app = data[IDS_INSTANCE_NAME]

    @route("ids", "/ryu/status", methods=["GET"])
    def status(self, req, **kwargs):
        return json_response(self.ids_app.get_status_payload())

    @route("ids", "/ryu/stats", methods=["GET"])
    def stats(self, req, **kwargs):
        return json_response(self.ids_app.get_stats_payload())

    @route("ids", "/ryu/alerts", methods=["GET"])
    def alerts(self, req, **kwargs):
        return json_response(self.ids_app.get_alerts_payload())

    @route("ids", "/ryu/datapaths", methods=["GET"])
    def datapaths(self, req, **kwargs):
        return json_response(self.ids_app.get_datapaths_payload())

    @route("ids", "/ryu/flows", methods=["GET"])
    def flows(self, req, **kwargs):
        return json_response(self.ids_app.get_flows_payload())

    @route("ids", "/ryu/meters", methods=["GET"])
    def meters(self, req, **kwargs):
        return json_response(self.ids_app.get_meters_payload())

    @route("ids", "/ryu/mitigations", methods=["GET"])
    def mitigations(self, req, **kwargs):
        return json_response(self.ids_app.get_mitigations_payload())

    @route("ids", "/ryu/reset-controller-state", methods=["POST"])
    def reset_controller_state(self, req, **kwargs):
        return json_response(self.ids_app.reset_controller_state())
