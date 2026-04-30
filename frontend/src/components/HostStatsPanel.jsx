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
            </tr>
          </thead>
          <tbody>
            {hosts.map((host) => (
              <tr key={host.host}>
                <td className="mono">{host.host}</td>
                <td className="mono">{host.ip}</td>
                <td>{host.role}</td>
                <td>{formatNumber(host.packet_rate)}</td>
                <td>{formatNumber(host.byte_rate)}</td>
                <td>
                  <span className={`badge badge-${host.status || "idle"}`}>
                    {host.status || "idle"}
                  </span>
                </td>
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

export default HostStatsPanel;
