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
      ├─ Ryu WSGI REST API (:8080) for controller-owned SDN state
      └─ Mininet command server (127.0.0.1:9001) for demo traffic
```

Ryu monitors OpenFlow flow stats, detects randomized flooding behavior, installs drop rules for clear single-source floods, installs OpenFlow 1.3 meters for multi-source floods, and exposes controller-owned runtime state through its native WSGI REST API. FastAPI keeps the React API origin stable, proxies Ryu state, and owns Mininet/demo orchestration.

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

Fill in the environment variables for the frontend:

```bash
cp frontend/.env.example frontend/.env
```

Fill in the value of `VITE_API_BASE_URL` with your VM's IP Address

## Run Everything

Start these commands in separate terminals (In your VM):

- Enable sudo access for the current session (this allows the backend to run `ovs-ofctl` commands remotely)

- Start Ryu controller. Make sure the virtual environment that has Ryu installed is activated before running `ryu-manager`.
```bash
source venv/bin/activate
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

<img width="477" height="298" alt="image" src="https://github.com/user-attachments/assets/1babbb4a-a9ad-4d7e-ad3b-2fec4d892e1d" />


My frontend and backend servers can be accessed at `http://172.16.64.133:5173` and `http://172.16.64.133/api/health` respectively.


## Verify OpenFlow:

```bash
# Run this command in a terminal in your VM, not your local machine
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```
Example result:

<img width="972" height="47" alt="image" src="https://github.com/user-attachments/assets/7fad2f71-3267-40af-884b-eb51aeacfc1c" />

To inspect rate-limit meters after a multi-source flood:

```bash
# Run this command in a terminal in your VM, not your local machine
sudo ovs-ofctl -O OpenFlow13 dump-meters s1
sudo ovs-ofctl -O OpenFlow13 meter-stats s1
```

## Demo Flow

1. Start all services.
2. Open the dashboard.
3. Click `Start Normal Traffic`.
4. All hosts begin with the `normal` role and send low-rate randomized traffic in a balanced cycle.
5. Click `Start Single-Source Flood`.
6. Mininet randomly chooses one attacker and one distinct victim.
7. Ryu detects the high source-to-destination packet rate.
8. Ryu installs a high-priority drop rule for the attacking flow:

```text
priority=100, ip, nw_src=<attacker_ip>, nw_dst=<victim_ip>, actions=drop
```

9. The dashboard shows the alert, blocked attacker status, protected victim status, and active drop rule.
10. Click `Reset Demo`.
11. Click `Start Multi-Source Flood`.
12. Mininet randomly chooses one victim and three attacking sources.
13. Ryu detects multiple moderate-rate sources targeting the same victim.
14. Ryu installs OpenFlow 1.3 meters and meter-backed forwarding rules:

```text
meter=<meter_id>,actions=output:<port>
```

15. The dashboard shows rate-limited attackers, the attacked victim, active meter rules, and meter counters.
16. Click `Stop Traffic` or `Reset Demo` to clear temporary runtime state.

## VM Smoke Test

This project is tested in a Linux VM at `172.16.64.133`.

```bash
ssh jonathan@172.16.64.133
```

Mininet and Open vSwitch commands must run inside the VM and require `sudo`. For the `jonathan` VM account, the sudo password is `jonathan`.

Manual smoke test:

1. Start Ryu, Mininet, backend, and frontend in the VM.
2. Trigger normal traffic and verify all hosts show low activity with no mitigation.
3. Trigger single-source flood multiple times and verify attacker/victim vary, IDS installs a drop rule, and the dashboard marks the attacker blocked.
4. Trigger multi-source flood multiple times and verify victim varies, `ovs-ofctl -O OpenFlow13 dump-meters s1` shows meters, and flow rules show meter actions.
5. Verify `Stop Traffic`, `Reset Demo`, and `Refresh Flow Table` still work.

## API

```text
GET  /api/health
GET  /api/status
GET  /api/stats
GET  /api/alerts
GET  /api/flows
GET  /api/meters
POST /api/traffic/normal/start
POST /api/demo/single-source-flood/start
POST /api/demo/multi-source-flood/start
POST /api/traffic/stop
POST /api/reset
POST /api/flows/refresh
```

## Mininet Command Server

`mininet/topology.py` starts a localhost TCP server on port `9001`.

Supported JSON commands:

```json
{"action": "start_normal"}
{"action": "start_single_source_flood"}
{"action": "start_multi_source_flood"}
{"action": "stop_traffic"}
{"action": "reset"}
```

FastAPI sends these commands when the dashboard buttons are clicked. If the command server or Ryu WSGI API is not running, the backend keeps synthetic fallback state in memory so the dashboard can still be previewed.

## Ryu WSGI API

```text
GET  /ryu/status
GET  /ryu/stats
GET  /ryu/alerts
GET  /ryu/datapaths
GET  /ryu/flows
GET  /ryu/meters
GET  /ryu/mitigations
POST /ryu/reset-controller-state
```

FastAPI calls these endpoints on `http://127.0.0.1:8080` by default. Override the target with `RYU_REST_BASE_URL` if Ryu is exposed elsewhere.

## Stop

```bash
scripts/stop_all.sh
```
