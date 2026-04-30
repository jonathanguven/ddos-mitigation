import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, RadioTower } from "lucide-react";
import { api } from "./api.js";
import AlertsPanel from "./components/AlertsPanel.jsx";
import ControlPanel from "./components/ControlPanel.jsx";
import FlowRulesPanel from "./components/FlowRulesPanel.jsx";
import HostStatsPanel from "./components/HostStatsPanel.jsx";
import MeterPanel from "./components/MeterPanel.jsx";
import MetricsChart from "./components/MetricsChart.jsx";
import TopologyView from "./components/TopologyView.jsx";

const emptyStats = { hosts: [], history: [] };
const emptyAlerts = { alerts: [] };
const emptyFlows = { flows: [], raw: [], error: null };
const emptyMeters = { meters: [], raw: [], error: null };

function App() {
  const [status, setStatus] = useState({
    demo_state: "idle",
    ryu_running: false,
    mininet_running: false,
    last_updated: "",
  });
  const [stats, setStats] = useState(emptyStats);
  const [alerts, setAlerts] = useState(emptyAlerts);
  const [flows, setFlows] = useState(emptyFlows);
  const [meters, setMeters] = useState(emptyMeters);
  const [busyAction, setBusyAction] = useState("");
  const [error, setError] = useState("");

  const refreshAll = useCallback(async () => {
    try {
      const [nextStatus, nextStats, nextAlerts, nextFlows, nextMeters] = await Promise.all([
        api.status(),
        api.stats(),
        api.alerts(),
        api.flows(),
        api.meters(),
      ]);
      setStatus(nextStatus);
      setStats(nextStats);
      setAlerts(nextAlerts);
      setFlows(nextFlows);
      setMeters(nextMeters);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => {
    refreshAll();
    const timer = window.setInterval(refreshAll, 1000);
    return () => window.clearInterval(timer);
  }, [refreshAll]);

  const runAction = useCallback(
    async (name, action) => {
      setBusyAction(name);
      setError("");
      try {
        await action();
        await refreshAll();
      } catch (err) {
        setError(err.message);
      } finally {
        setBusyAction("");
      }
    },
    [refreshAll],
  );

  const summary = useMemo(() => {
    const hosts = stats.hosts || [];
    const blocked = hosts.filter((host) => host.status === "blocked").length;
    const rateLimited = hosts.filter((host) => host.status === "rate_limited").length;
    const active = hosts.filter((host) =>
      ["active", "receiving", "under_attack", "protected"].includes(host.status),
    ).length;
    return { blocked, rateLimited, active };
  }, [stats.hosts]);

  return (
    <main className="app-shell">
      <header className="app-header">
        <div>
          <div className="eyebrow">OpenFlow 1.3 demo</div>
          <h1>SDN IDS + DDoS Mitigation Dashboard</h1>
        </div>
        <div className="header-status">
          <StatusPill label="Ryu" active={status.ryu_running} />
          <StatusPill label="Mininet" active={status.mininet_running} />
          <div className={`state-chip state-${status.demo_state}`}>
            <Activity size={16} />
            {status.demo_state}
          </div>
        </div>
      </header>

      {error && <div className="error-banner">{error}</div>}

      <section className="summary-strip" aria-label="Runtime summary">
        <div>
          <span className="summary-label">Active hosts</span>
          <strong>{summary.active}</strong>
        </div>
        <div>
          <span className="summary-label">Blocked sources</span>
          <strong>{summary.blocked}</strong>
        </div>
        <div>
          <span className="summary-label">Rate limited</span>
          <strong>{summary.rateLimited}</strong>
        </div>
        <div>
          <span className="summary-label">Alerts</span>
          <strong>{alerts.alerts?.length || 0}</strong>
        </div>
        <div>
          <span className="summary-label">Meters</span>
          <strong>{meters.meters?.length || 0}</strong>
        </div>
      </section>

      <section className="dashboard-grid">
        <TopologyView hosts={stats.hosts || []} status={status} />
        <HostStatsPanel hosts={stats.hosts || []} />
        <AlertsPanel alerts={alerts.alerts || []} />
        <ControlPanel
          busyAction={busyAction}
          onStartNormal={() =>
            runAction("normal", api.startNormalTraffic)
          }
          onStartSingleSource={() =>
            runAction("single-source", api.startSingleSourceFlood)
          }
          onStartMultiSource={() =>
            runAction("multi-source", api.startMultiSourceFlood)
          }
          onStop={() => runAction("stop", api.stopTraffic)}
          onReset={() => runAction("reset", api.resetDemo)}
          onRefreshFlows={() => runAction("flows", api.refreshFlows)}
        />
        <MetricsChart history={stats.history || []} />
        <FlowRulesPanel flows={flows.flows || []} error={flows.error} raw={flows.raw || []} />
        <MeterPanel meters={meters.meters || []} error={meters.error} raw={meters.raw || []} />
      </section>
    </main>
  );
}

function StatusPill({ label, active }) {
  return (
    <div className={`status-pill ${active ? "online" : "offline"}`}>
      <RadioTower size={15} />
      <span>{label}</span>
    </div>
  );
}

export default App;
