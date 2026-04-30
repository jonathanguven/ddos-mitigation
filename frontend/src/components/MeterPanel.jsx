function MeterPanel({ meters, error, raw }) {
  return (
    <section className="panel meters-panel">
      <div className="panel-heading">
        <h2>OpenFlow Meters</h2>
        <span className="panel-meta">ovs-ofctl dump-meters s1</span>
      </div>
      {error && <div className="inline-warning">{error}</div>}
      <div className="meter-list">
        {meters.length === 0 && !error && <div className="empty-state">No meters</div>}
        {meters.map((meter, index) => (
          <article className="meter-row" key={`${meter.raw}-${index}`}>
            <div className="flow-topline">
              <strong>Meter ID: {meter.meter_id ?? "unknown"}</strong>
              <span className="meter-action">RATE_LIMIT</span>
            </div>
            <dl>
              <div>
                <dt>Rate</dt>
                <dd>{formatNumber(meter.rate_kbps)} kbps</dd>
              </div>
              <div>
                <dt>Burst</dt>
                <dd>{formatNumber(meter.burst_size)}</dd>
              </div>
              <div>
                <dt>Packets</dt>
                <dd>{formatNumber(meter.packet_count)}</dd>
              </div>
              <div>
                <dt>Bytes</dt>
                <dd>{formatNumber(meter.byte_count)}</dd>
              </div>
            </dl>
            <p>
              <span>Raw:</span> {meter.raw}
            </p>
          </article>
        ))}
      </div>
      {raw.length > 0 && meters.length === 0 && (
        <pre className="raw-flows">{raw.join("\n")}</pre>
      )}
    </section>
  );
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

export default MeterPanel;
