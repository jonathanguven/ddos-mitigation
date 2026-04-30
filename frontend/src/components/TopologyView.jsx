import { Server, Shield, Waypoints } from "lucide-react";

const NODE_POSITIONS = {
  h1: { x: 76, y: 88 },
  h2: { x: 76, y: 208 },
  h3: { x: 76, y: 328 },
  h4: { x: 518, y: 128 },
  s1: { x: 292, y: 205 },
  h5: { x: 518, y: 290 },
  c0: { x: 292, y: 372 },
};

const LINKS = [
  ["h1", "s1"],
  ["h2", "s1"],
  ["h3", "s1"],
  ["h4", "s1"],
  ["h5", "s1"],
  ["c0", "s1"],
];

function TopologyView({ hosts, status }) {
  const hostByName = Object.fromEntries(hosts.map((host) => [host.host, host]));

  return (
    <section className="panel topology-panel">
      <div className="panel-heading">
        <h2>Topology</h2>
        <span className="panel-meta">s1 / c0 / h1-h5</span>
      </div>
      <svg viewBox="0 0 610 430" role="img" aria-label="SDN demo topology">
        {LINKS.map(([from, to]) => {
          const a = NODE_POSITIONS[from];
          const b = NODE_POSITIONS[to];
          return (
            <line
              key={`${from}-${to}`}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              className={from === "c0" ? "topology-link controller-link" : "topology-link"}
            />
          );
        })}
        <NetworkNode
          name="s1"
          label="Open vSwitch"
          x={NODE_POSITIONS.s1.x}
          y={NODE_POSITIONS.s1.y}
          tone="blue"
          icon="switch"
        />
        <NetworkNode
          name="c0"
          label="Ryu Controller"
          x={NODE_POSITIONS.c0.x}
          y={NODE_POSITIONS.c0.y}
          tone="blue"
          icon="controller"
        />
        {["h1", "h2", "h3", "h4", "h5"].map((name) => {
          const host = hostByName[name] || {};
          return (
            <NetworkNode
              key={name}
              name={name}
              label={displayRole(host)}
              x={NODE_POSITIONS[name].x}
              y={NODE_POSITIONS[name].y}
              tone={nodeTone(host.status)}
              icon="host"
            />
          );
        })}
      </svg>
      <div className="legend">
        <LegendItem tone="normal" label="normal" />
        <LegendItem tone="suspicious" label="rate limited" />
        <LegendItem tone="danger" label="blocked" />
        <LegendItem tone="inactive" label="inactive" />
        <LegendItem tone="blue" label="control plane" />
      </div>
    </section>
  );
}

function NetworkNode({ name, label, x, y, tone, icon }) {
  const Icon = icon === "switch" ? Waypoints : icon === "controller" ? Shield : Server;
  return (
    <g className={`network-node node-${tone}`} transform={`translate(${x} ${y})`}>
      <circle r="33" />
      <foreignObject x="-15" y="-18" width="30" height="30">
        <div className="node-icon">
          <Icon size={28} strokeWidth={2.2} />
        </div>
      </foreignObject>
      <text y="52" textAnchor="middle" className="node-name">
        {name}
      </text>
      <text y="71" textAnchor="middle" className="node-label">
        {label}
      </text>
    </g>
  );
}

function LegendItem({ tone, label }) {
  return (
    <span>
      <i className={`legend-dot node-${tone}`} />
      {label}
    </span>
  );
}

function displayRole(host = {}) {
  if (host.status === "blocked" || host.mitigation === "drop") {
    return "attacker";
  }
  if (
    host.status === "rate_limited" ||
    host.status === "suspicious" ||
    host.mitigation === "rate_limit"
  ) {
    return "suspicious";
  }
  if (host.status === "under_attack" || host.status === "protected") {
    return "victim";
  }
  return "normal";
}

function nodeTone(hostStatus) {
  if (hostStatus === "blocked") {
    return "danger";
  }
  if (hostStatus === "rate_limited" || hostStatus === "suspicious") {
    return "suspicious";
  }
  if (hostStatus === "under_attack") {
    return "danger";
  }
  if (hostStatus === "active" || hostStatus === "receiving" || hostStatus === "protected") {
    return "normal";
  }
  return "inactive";
}

export default TopologyView;
