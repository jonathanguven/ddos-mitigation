# SDN IDS + DDoS Mitigation Dashboard

Working demo system for:

- Vite + React dashboard
- FastAPI control API
- Ryu OpenFlow 1.3 IDS controller
- Mininet + Open vSwitch topology
- Traffic controls, host statistics, IDS alerts, and mitigation flow visibility

## Architecture

```text
Frontend Dashboard
      ↓
FastAPI Backend
      ↓
Mininet/Ryu/OVS
```

Ryu monitors OpenFlow flow stats, detects high-rate `h1 -> h5` traffic, installs a high-priority drop rule on `s1`, and writes runtime state to JSON files read by FastAPI.

## Install

Run on a Linux VM or host with Mininet/Open vSwitch support.

```bash
sudo apt update
sudo apt install mininet openvswitch-switch iperf python3-pip nodejs npm
pip install ryu fastapi uvicorn
```

Frontend dependencies:

```bash
cd frontend
npm install
```

## Run Everything

Start these commands in separate terminals (In your VM):

- Start Ryu controller
```bash
ryu-manager --ofp-tcp-listen-port 6653 ryu_app/ids_controller.py
```

- Initialize Mininet topology
```bash
sudo python3 mininet/topology.py
```

- Initialize backend server
```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

- Initialize frontend dashboard
```bash
cd frontend
npm install && npm run dev -- --host 0.0.0.0
```

### Frontend Access
Since the servers run on Linux Virtual Machines, the frontend server can be accessed at:
`http://<INSERT_VM_IP_ADDRESS>:5173`

The backend server can be accessed at:
`http://<INSERT_VM_IP_ADDRESS>/api/health`

For example, given the ssh connection settings for my virtual machine:


My frontend and backend servers can be accessed at `http://172.16.64.133:5173` and `http://172.16.64.133/api/health` respectively.


## Verify OpenFlow:

```bash
# Run this command in a terminal in your VM, not your local machine
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

## Demo Flow

1. Start all services.
2. Open the dashboard.
3. Click `Start Normal Traffic`.
4. Normal hosts show low-rate green activity.
5. Click `Start Attack Traffic`.
6. `h1` sends high-rate UDP traffic to `h5`.
7. Ryu detects the high packet rate.
8. Ryu installs:

```text
priority=100, ip, nw_src=10.0.0.1, nw_dst=10.0.0.5, actions=drop
```

9. The dashboard shows the alert, blocked attacker status, and active drop rule.
10. Click `Reset Demo` to clear temporary state and mitigation visibility.

## API

```text
GET  /api/health
GET  /api/status
GET  /api/stats
GET  /api/alerts
GET  /api/flows
POST /api/traffic/normal/start
POST /api/traffic/attack/start
POST /api/traffic/stop
POST /api/reset
POST /api/flows/refresh
```

## Mininet Command Server

`mininet/topology.py` starts a localhost TCP server on port `9001`.

Supported JSON commands:

```json
{"action": "start_normal"}
{"action": "start_attack"}
{"action": "stop_traffic"}
{"action": "reset"}
```

FastAPI sends these commands when the dashboard buttons are clicked. If the command server is not running, the backend writes synthetic fallback state so the dashboard can still be previewed.

## State Files

```text
/tmp/sdn_ids_stats.json
/tmp/sdn_ids_alerts.json
/tmp/sdn_ids_state.json
```

## Stop

```bash
scripts/stop_all.sh
```
