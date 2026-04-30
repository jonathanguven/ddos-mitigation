function HostStatsPanel({ hosts }) {
  return (
    <section className="panel host-panel">
      <div className="panel-heading">
        <h2>Host Statistics</h2>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>IP</th>
              <th>Role</th>
              <th>Packets/s</th>
              <th>Bytes/s</th>
              <th>Status</th>
              <th>Mitigation</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((host) => (
              <tr key={host.host}>
                <td className="mono">{host.host}</td>
                <td className="mono">{host.ip}</td>
                <td>{displayRole(host)}</td>
                <td>{formatNumber(host.packet_rate)}</td>
                <td>{formatNumber(host.byte_rate)}</td>
                <td>
                  <span className={`badge badge-${host.status || "idle"}`}>
                    {host.status || "idle"}
                  </span>
                </td>
                <td>{formatMitigation(host.mitigation)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function formatMitigation(value) {
  if (!value) {
    return "None";
  }
  return value === "rate_limit" ? "Meter" : "Drop";
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

export default HostStatsPanel;
