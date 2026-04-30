#!/usr/bin/env python3
"""Single-switch Mininet topology for the SDN IDS demo.

Hosts:
  h1 10.0.0.1
  h2 10.0.0.2
  h3 10.0.0.3
  h4 10.0.0.4
  h5 10.0.0.5

The script also starts a small localhost TCP command server on port 9001 so the FastAPI backend can trigger demo traffic without attaching to the Mininet CLI.
"""

import json
import os
import random
import socketserver
import threading

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


COMMAND_HOST = "127.0.0.1"
COMMAND_PORT = 9001
HOSTS = {
    "h1": "10.0.0.1",
    "h2": "10.0.0.2",
    "h3": "10.0.0.3",
    "h4": "10.0.0.4",
    "h5": "10.0.0.5",
}
HOST_NAMES = list(HOSTS)
TRAFFIC_DURATION_SECONDS = 60
NORMAL_RATES = ["500K", "650K", "750K", "850K", "900K"]
SINGLE_SOURCE_FLOOD_RATE = "100M"
MULTI_SOURCE_FLOOD_RATE = "8M"


class DemoTopo(Topo):
    """One OpenFlow 1.3 OVS switch with five hosts."""

    def build(self):
        switch = self.addSwitch("s1", protocols="OpenFlow13")

        for name, ip in HOSTS.items():
            host = self.addHost(name, ip=f"{ip}/24")
            self.addLink(host, switch)


class DemoCommandServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, net):
        super().__init__(server_address, handler_class)
        self.net = net


class DemoCommandHandler(socketserver.BaseRequestHandler):
    """Receives JSON commands and executes them inside Mininet host namespaces."""

    def handle(self):
        raw = self.request.recv(4096).decode("utf-8").strip()
        try:
            payload = json.loads(raw)
            action = payload.get("action")
            result = self.dispatch(action)
            response = {"ok": True, **result}
        except Exception as exc:  # pragma: no cover - runtime safety for demo CLI
            response = {"ok": False, "error": str(exc)}

        self.request.sendall((json.dumps(response) + "\n").encode("utf-8"))

    def dispatch(self, action):
        if action == "start_normal":
            return self.start_normal()
        if action == "start_single_source_flood":
            return self.start_single_source_flood()
        if action == "start_multi_source_flood":
            return self.start_multi_source_flood()
        if action == "stop_traffic":
            return self.stop_traffic()
        if action == "reset":
            self.stop_traffic()
            os.system("ovs-ofctl -O OpenFlow13 del-flows s1 'priority=100,ip'")
            os.system("ovs-ofctl -O OpenFlow13 del-flows s1 'priority=90,ip'")
            os.system("ovs-ofctl -O OpenFlow13 del-meters s1")
            return {"message": "Traffic stopped and OpenFlow demo state cleared"}

        raise ValueError(f"Unsupported action: {action}")

    def host(self, name):
        return self.server.net.get(name)

    def ensure_iperf_servers(self):
        for name in HOST_NAMES:
            self.host(name).cmd(
                "pgrep -f 'iperf -s -u' >/dev/null || "
                f"iperf -s -u > /tmp/{name}_iperf_server.log 2>&1 &"
            )

    def stop_clients(self):
        for name in HOST_NAMES:
            host = self.host(name)
            host.cmd("pkill -f 'iperf -u -c' || true")
            host.cmd("pkill -f ping || true")

    def start_udp_client(self, src, dst, rate, label):
        self.host(src).cmd(
            f"iperf -u -c {HOSTS[dst]} -b {rate} -t {TRAFFIC_DURATION_SECONDS} "
            f"> /tmp/{src}_{label}.log 2>&1 &"
        )

    def start_normal(self):
        self.stop_clients()
        self.ensure_iperf_servers()
        cycle = HOST_NAMES[:]
        random.shuffle(cycle)
        flows = []
        for index, src in enumerate(cycle):
            dst = cycle[(index + 1) % len(cycle)]
            rate = NORMAL_RATES[index % len(NORMAL_RATES)]
            self.start_udp_client(src, dst, rate, "normal")
            flows.append(f"{src}->{dst}")
        return {
            "message": f"Normal traffic started across {', '.join(flows)}",
            "flows": flows,
        }

    def start_single_source_flood(self):
        self.stop_clients()
        self.ensure_iperf_servers()
        attacker, victim = random.sample(HOST_NAMES, 2)
        self.start_udp_client(attacker, victim, SINGLE_SOURCE_FLOOD_RATE, "single_source_flood")
        return {
            "message": f"Single-source flood started from {attacker} to {victim}",
            "attacker": attacker,
            "victim": victim,
            "attacker_ip": HOSTS[attacker],
            "victim_ip": HOSTS[victim],
        }

    def start_multi_source_flood(self):
        self.stop_clients()
        self.ensure_iperf_servers()
        victim = random.choice(HOST_NAMES)
        candidates = [name for name in HOST_NAMES if name != victim]
        attackers = random.sample(candidates, 3)
        standby = sorted(set(candidates) - set(attackers))
        for attacker in attackers:
            self.start_udp_client(attacker, victim, MULTI_SOURCE_FLOOD_RATE, "multi_source_flood")
        return {
            "message": (
                "Multi-source flood started from "
                f"{', '.join(attackers)} to {victim}"
            ),
            "attackers": attackers,
            "victim": victim,
            "attacker_ips": [HOSTS[name] for name in attackers],
            "victim_ip": HOSTS[victim],
            "standby_hosts": standby,
        }

    def stop_traffic(self):
        for name in HOST_NAMES:
            host = self.host(name)
            host.cmd("pkill -f iperf || true")
            host.cmd("pkill -f ping || true")
        return {"message": "Traffic stopped"}


def start_command_server(net):
    server = DemoCommandServer((COMMAND_HOST, COMMAND_PORT), DemoCommandHandler, net)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    info(f"*** Mininet command server listening on {COMMAND_HOST}:{COMMAND_PORT}\n")
    return server


def main():
    setLogLevel("info")

    topo = DemoTopo()
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch, autoSetMacs=True)
    net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653,
        protocols="OpenFlow13",
    )

    info("*** Starting network\n")
    net.start()
    for switch in net.switches:
        switch.cmd(f"ovs-vsctl set bridge {switch.name} protocols=OpenFlow13")

    info("*** Starting host iperf UDP servers\n")
    for name in HOST_NAMES:
        net.get(name).cmd(f"iperf -s -u > /tmp/{name}_iperf_server.log 2>&1 &")

    server = start_command_server(net)

    info("*** Network ready. Use the CLI or dashboard controls.\n")
    try:
        CLI(net)
    finally:
        info("*** Shutting down command server\n")
        server.shutdown()
        server.server_close()
        info("*** Stopping network\n")
        net.stop()


if __name__ == "__main__":
    main()
