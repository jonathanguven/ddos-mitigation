function AlertsPanel({ alerts }) {
  return (
    <section className="panel alerts-panel">
      <div className="panel-heading">
        <h2>IDS Alerts</h2>
      </div>
      <div className="alert-list">
        {alerts.length === 0 && <div className="empty-state">No alerts</div>}
        {alerts
          .slice()
          .reverse()
          .map((alert, index) => (
            <article
              className={`alert-row alert-${alert.level || "info"}`}
              key={`${alert.time}-${index}`}
            >
              <time>{alert.time}</time>
              <span>
                {alert.mitigation && (
                  <strong className={`mitigation-label mitigation-${alert.mitigation}`}>
                    {formatMitigation(alert.mitigation)}
                  </strong>
                )}
                {alert.message}
              </span>
            </article>
          ))}
      </div>
    </section>
  );
}

function formatMitigation(value) {
  return value === "rate_limit" ? "RATE_LIMIT" : value.toUpperCase();
}

export default AlertsPanel;
