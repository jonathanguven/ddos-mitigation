import { useState } from "react";

function FlowRulesPanel({ flows, error, raw }) {
  const [showAll, setShowAll] = useState(false);
  const visibleFlows = showAll ? flows : flows.filter(isDemoRelevantFlow);
  const hiddenFlowCount = flows.length - visibleFlows.length;

  return (
    <section className="panel flows-panel">
      <div className="panel-heading">
        <h2>OpenFlow Rules</h2>
        <div className="flow-heading-actions">
          <span className="panel-meta">Ryu flow stats</span>
          {flows.length > 0 && (
            <button
              className="flow-filter-toggle"
              onClick={() => setShowAll((current) => !current)}
              type="button"
            >
              {showAll ? "Show demo rules" : "Show all rules"}
            </button>
          )}
        </div>
      </div>
      {error && <div className="inline-warning">{error}</div>}
      <div className="flow-list">
        {flows.length === 0 && !error && <div className="empty-state">No flow rules</div>}
        {flows.length > 0 && visibleFlows.length === 0 && !error && (
          <div className="empty-state">No IP or mitigation rules</div>
        )}
        {!showAll && hiddenFlowCount > 0 && (
          <div className="flow-filter-note">
            Hiding {hiddenFlowCount} MAC/ARP forwarding {hiddenFlowCount === 1 ? "rule" : "rules"}.
          </div>
        )}
        {visibleFlows.map((flow, index) => (
          <article className="flow-row" key={`${flow.raw}-${index}`}>
            <div className="flow-topline">
              <div className="flow-title">
                <span className="flow-order">#{flow.table_order || index + 1}</span>
                <strong>Switch: {flow.switch}</strong>
              </div>
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
  if (isIpForwarding(flow)) {
    return "IP forwarding";
  }
  if (isMacForwarding(flow)) {
    return "MAC/ARP forwarding";
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

function isDemoRelevantFlow(flow) {
  return isDrop(flow.actions) || isMeter(flow) || isIpForwarding(flow);
}

function isIpForwarding(flow) {
  return Number(flow.priority) >= 10 && /\b(?:ip|nw_src|nw_dst)\b/i.test(flow.match || "");
}

function isMacForwarding(flow) {
  return Number(flow.priority) <= 1 || /\b(?:dl_src|dl_dst|eth_src|eth_dst|arp)\b/i.test(flow.match || "");
}

export default FlowRulesPanel;
