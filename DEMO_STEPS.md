# Project Demo Steps

Use this as a presenter checklist for the SDN IDS + DDoS mitigation demo.

## 1. Prepare the Demo Environment

1. SSH into the Linux VM or open a terminal on the machine running Mininet/Open vSwitch.
2. Go to the project folder:

   ```bash
   cd /path/to/ddos-mitigation
   ```

3. Make sure dependencies are installed:

   ```bash
   sudo apt update
   sudo apt install mininet openvswitch-switch iperf python3-pip nodejs npm
   pip install ryu fastapi uvicorn
   cd frontend && npm install && cd ..
   ```

4. If the frontend `.env` file is missing, create it from the example and set the backend URL:

   ```bash
   cp frontend/.env.example frontend/.env
   ```

5. Tell the audience the purpose of the project:

   > This project demonstrates an SDN-based intrusion detection and mitigation system. Ryu monitors OpenFlow traffic statistics, detects DDoS behavior, and automatically installs OpenFlow rules or meters to mitigate attacks.

## 2. Start the System

Start the services in separate terminals, or use the helper script if `tmux` is installed:

```bash
scripts/start_all.sh
```

If starting manually, run these commands from the project root:

1. Start the Ryu controller:

   ```bash
   source venv/bin/activate
   ryu-manager --ofp-tcp-listen-port 6653 ryu_app/ids_controller.py
   ```

2. Start the Mininet topology:

   ```bash
   sudo python3 mininet/topology.py
   ```

3. Start the FastAPI backend:

   ```bash
   cd backend
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

4. Start the React frontend:

   ```bash
   cd frontend
   npm run dev -- --host 0.0.0.0
   ```

5. Open the dashboard:

   ```text
   http://<VM_IP_ADDRESS>:5173
   ```

6. Confirm the dashboard shows:

   - `Ryu` online
   - `Mininet` online
   - Demo state is `idle`
   - No IDS alerts yet
   - No blocked or rate-limited hosts yet

## 3. Show the Baseline Topology

1. Point out the dashboard sections:

   - Topology view
   - Host statistics
   - IDS alerts
   - Controls
   - Metrics chart
   - Evaluation metrics
   - OpenFlow rules
   - OpenFlow meters

2. Explain the baseline:

   > At the beginning, all hosts are normal. The controller has not detected an attack, so there are no mitigation rules or meters installed.

3. Optional terminal verification:

   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-flows s1
   ```

4. Mention that this command shows the switch flow table controlled by Ryu.

## 4. Demonstrate Normal Traffic

1. In the dashboard, click `Start Normal Traffic`.
2. Wait a few seconds for the metrics to update.
3. Point out:

   - Hosts become active.
   - Traffic appears in the metrics chart.
   - IDS alerts should remain empty or non-critical.
   - No hosts should be blocked.
   - No OpenFlow meters should appear.

4. Say:

   > Normal traffic is intentionally low-rate and distributed. The IDS should observe activity without triggering mitigation.

5. Click `Stop Traffic` before moving to the attack scenarios.

## 5. Demonstrate Single-Source Flood Detection

1. Click `Reset Demo`.
2. Click `Start Single-Source Flood`.
3. Wait for the dashboard to update.
4. Point out:

   - One host is selected as the attacker.
   - One different host is selected as the victim.
   - The IDS alerts panel reports a single-source flood.
   - The summary strip shows one blocked source.
   - The topology or host stats show the attacker as blocked and the victim as protected or under attack.

5. In the OpenFlow rules panel, point out the `DROP` rule.
6. Explain:

   > For a high-rate single-source flood, the controller installs a high-priority drop rule matching the attacker and victim IP pair.

7. Optional terminal verification:

   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-flows s1
   ```

8. Look for a rule shaped like:

   ```text
   priority=100, ip, nw_src=<attacker_ip>, nw_dst=<victim_ip>, actions=drop
   ```

9. Say:

   > This proves the mitigation is enforced in the switch, not only displayed in the web interface.

## 6. Demonstrate Multi-Source Flood Mitigation

1. Click `Reset Demo`.
2. Click `Start Multi-Source Flood`.
3. Wait for the dashboard to update.
4. Point out:

   - Multiple attacking hosts target the same victim.
   - The IDS alerts panel reports a multi-source flood.
   - The summary strip shows rate-limited sources.
   - The OpenFlow meters panel shows active meters.
   - The OpenFlow rules panel shows `RATE_LIMIT` actions.

5. Explain:

   > For a multi-source flood, dropping every source can be too aggressive. Instead, the controller installs OpenFlow meters to rate-limit suspicious traffic while still allowing forwarding.

6. Optional terminal verification:

   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-meters s1
   sudo ovs-ofctl -O OpenFlow13 meter-stats s1
   ```

7. In the flow table, look for rules shaped like:

   ```text
   meter=<meter_id>,actions=output:<port>
   ```

## 7. Show Reset and Recovery

1. Click `Stop Traffic`.
2. Click `Reset Demo`.
3. Click `Refresh Flow Table`.
4. Confirm:

   - Demo state returns to `idle`.
   - Alerts and temporary attack state are cleared.
   - Blocked and rate-limited counts return to zero.
   - Temporary mitigation rules/meters are removed or no longer active.

5. Say:

   > The reset flow clears runtime state so the system can run another scenario cleanly.

## 8. Suggested Closing Explanation

Use this short closing summary:

> The main result is that the SDN controller can observe live network behavior, classify different DDoS patterns, and apply mitigation directly through OpenFlow. Single-source floods are blocked with drop rules, while multi-source floods are rate-limited with OpenFlow meters. The dashboard provides visibility into detection, mitigation, host status, flow rules, and meter counters.

## 9. Demo Troubleshooting

- If the dashboard cannot connect, check the backend health endpoint:

  ```text
  http://<VM_IP_ADDRESS>:8000/api/health
  ```

- If Ryu is offline, restart:

  ```bash
  ryu-manager --ofp-tcp-listen-port 6653 ryu_app/ids_controller.py
  ```

- If Mininet is stuck, stop old Mininet state and restart:

  ```bash
  sudo mn -c
  sudo python3 mininet/topology.py
  ```

- If flow or meter data looks stale, click `Refresh Flow Table`.
- If the demo gets noisy, click `Stop Traffic`, then `Reset Demo`.
- To stop everything after the presentation:

  ```bash
  scripts/stop_all.sh
  ```
