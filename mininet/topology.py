#!/usr/bin/env python3
"""Single-switch Mininet topology for the SDN IDS demo.

Hosts:
  h1 attacker 10.0.0.1
  h2 normal   10.0.0.2
  h3 normal   10.0.0.3
  h4 normal   10.0.0.4
  h5 victim   10.0.0.5

The script also starts a small localhost TCP command server on port 9001 so the FastAPI backend can trigger demo traffic without attaching to the Mininet CLI.
"""

import json
import os
import socketserver
import threading

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


COMMAND_HOST = "127.0.0.1"
COMMAND_PORT = 9001
VICTIM_IP = "10.0.0.5"
ATTACKER_IP = "10.0.0.1"


class DemoTopo(Topo):
    """One OpenFlow 1.3 OVS switch with five hosts."""

    def build(self):
        switch = self.addSwitch("s1", protocols="OpenFlow13")

        hosts = {
            "h1": "10.0.0.1/24",
            "h2": "10.0.0.2/24",
            "h3": "10.0.0.3/24",
            "h4": "10.0.0.4/24",
            "h5": "10.0.0.5/24",
        }

        for name, ip in hosts.items():
            host = self.addHost(name, ip=ip)
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
        if action == "start_attack":
            return self.start_attack()
        if action == "stop_traffic":
            return self.stop_traffic()
        if action == "reset":
            self.stop_traffic()
            os.system(
                "ovs-ofctl -O OpenFlow13 del-flows s1 "
                "'priority=100,ip,nw_src=10.0.0.1,nw_dst=10.0.0.5'"
            )
            return {"message": "Traffic stopped and mitigation flow removed"}

        raise ValueError(f"Unsupported action: {action}")

    def host(self, name):
        return self.server.net.get(name)

    def ensure_iperf_server(self):
        h5 = self.host("h5")
        h5.cmd(
            "pgrep -f 'iperf -s -u' >/dev/null || "
            "iperf -s -u > /tmp/h5_iperf_server.log 2>&1 &"
        )

    def start_normal(self):
        self.ensure_iperf_server()
        self.host("h2").cmd("ping -i 0.5 10.0.0.5 > /tmp/h2_ping.log 2>&1 &")
        self.host("h3").cmd(
            "iperf -u -c 10.0.0.5 -b 1M -t 60 > /tmp/h3_iperf.log 2>&1 &"
        )
        self.host("h4").cmd(
            "iperf -u -c 10.0.0.5 -b 750K -t 60 > /tmp/h4_iperf.log 2>&1 &"
        )
        return {"message": "Normal traffic started"}

    def start_attack(self):
        self.ensure_iperf_server()
        self.host("h1").cmd(
            "iperf -u -c 10.0.0.5 -b 100M -t 60 > /tmp/h1_attack.log 2>&1 &"
        )
        return {"message": f"Attack traffic started from {ATTACKER_IP} to {VICTIM_IP}"}

    def stop_traffic(self):
        for name in ["h1", "h2", "h3", "h4", "h5"]:
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

    info("*** Starting victim iperf UDP server\n")
    net.get("h5").cmd("iperf -s -u > /tmp/h5_iperf_server.log 2>&1 &")

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
