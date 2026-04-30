function FlowRulesPanel({ flows, error, raw }) {
  return (
    <section className="panel flows-panel">
      <div className="panel-heading">
        <h2>OpenFlow Rules</h2>
        <span className="panel-meta">ovs-ofctl dump-flows s1</span>
      </div>
      {error && <div className="inline-warning">{error}</div>}
      <div className="flow-list">
        {flows.length === 0 && !error && <div className="empty-state">No flow rules</div>}
        {flows.map((flow, index) => (
          <article className="flow-row" key={`${flow.raw}-${index}`}>
            <div className="flow-topline">
              <strong>Switch: {flow.switch}</strong>
              <span className={actionClass(flow)}>
                {actionLabel(flow)}
              </span>
            </div>
            <dl>
              <div>
                <dt>Priority</dt>
                <dd>{flow.priority}</dd>
              </div>
              <div>
                <dt>Packets</dt>
                <dd>{Number(flow.packets || 0).toLocaleString()}</dd>
              </div>
              <div>
                <dt>Bytes</dt>
                <dd>{Number(flow.bytes || 0).toLocaleString()}</dd>
              </div>
            </dl>
            <p>
              <span>Match:</span> {flow.match}
            </p>
            <p>
              <span>Action:</span> {flow.actions}
            </p>
          </article>
        ))}
      </div>
      {raw.length > 0 && flows.length === 0 && (
        <pre className="raw-flows">{raw.join("\n")}</pre>
      )}
    </section>
  );
}

function isDrop(actions = "") {
  const normalized = actions.trim().toLowerCase();
  return normalized === "drop" || normalized === "";
}

function isMeter(flow) {
  return Boolean(flow.meter_id) || /meter[:=]\d+/i.test(flow.actions || "");
}

function actionLabel(flow) {
  if (isDrop(flow.actions)) {
    return "DROP";
  }
  if (isMeter(flow)) {
    return "RATE_LIMIT";
  }
  return "FORWARD";
}

function actionClass(flow) {
  if (isDrop(flow.actions)) {
    return "drop-action";
  }
  if (isMeter(flow)) {
    return "meter-action";
  }
  return "forward-action";
}

export default FlowRulesPanel;
