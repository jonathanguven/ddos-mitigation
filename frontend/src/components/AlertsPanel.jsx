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
              <span>{alert.message}</span>
            </article>
          ))}
      </div>
    </section>
  );
}

export default AlertsPanel;
