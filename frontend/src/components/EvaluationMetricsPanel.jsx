import { useEffect, useMemo, useState } from "react";

const SINGLE_SOURCE_THRESHOLD = 5_000;
const MULTI_SOURCE_THRESHOLD = 1_500;
const FREEZE_SETTLE_MS = 1_000;

function EvaluationMetricsPanel({ alerts, flows, history, hosts, meters }) {
  const computedRows = useMemo(
    () => buildEvaluationRows({ alerts, flows, history, hosts, meters }),
    [alerts, flows, history, hosts, meters],
  );
  const [frozenRows, setFrozenRows] = useState([]);

  useEffect(() => {
    if (computedRows.length === 0) {
      setFrozenRows([]);
      return;
    }

    setFrozenRows((currentRows) => mergeFrozenRows(currentRows, computedRows));
  }, [computedRows]);

  const rows = frozenRows.length ? frozenRows : computedRows;

  return (
    <section className="panel evaluation-panel">
      <div className="panel-heading">
        <h2>Evaluation Metrics</h2>
        <span className="panel-meta">Per attack summary</span>
      </div>
      <div className="table-wrap">
        <table className="evaluation-table">
          <thead>
            <tr>
              <th>Attack</th>
              <th>Path</th>
              <th>Detection Time</th>
              <th>Mitigation Response</th>
              <th>Throughput Before</th>
              <th>Throughput After</th>
              <th>Packet Loss</th>
              <th>Network Stability</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td className="empty-table-cell" colSpan={8}>
                  No evaluated attacks yet
                </td>
              </tr>
            )}
            {rows.map((row) => (
              <tr key={row.id}>
                <td>
                  <span className={`metric-attack metric-${row.mitigation}`}>
                    {row.attack}
                  </span>
                </td>
                <td className="mono">{row.path}</td>
                <td>{row.detectionTime}</td>
                <td>{row.responseTime}</td>
                <td>{row.throughputBefore}</td>
                <td>{row.throughputAfter}</td>
                <td>{row.packetLoss}</td>
                <td>
                  <span className={`stability-pill stability-${row.stabilityTone}`}>
                    {row.networkStability}
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

function buildEvaluationRows({ alerts = [], flows = [], history = [], hosts = [], meters = [] }) {
  return dedupeAttackAlerts(alerts)
    .slice(-8)
    .reverse()
    .map((alert, index) => {
      const mitigation = alert.mitigation || inferMitigation(alert);
      const threshold =
        alert.alert_type === "single_source_flood"
          ? SINGLE_SOURCE_THRESHOLD
          : MULTI_SOURCE_THRESHOLD;
      const attackCurve = analyzeAttackCurve(history, alert.time, threshold);
      const mitigationInstalled = hasMatchingMitigation(alert, flows, meters);
      const stability = estimateStability(hosts, alert);
      const detectionMs = estimateControllerDetectionMs(alert);
      const responseMs = estimateControllerMitigationMs(alert);

      return {
        id: `${alert.time}-${alert.alert_type}-${index}`,
        signature: attackSignature(alert),
        attack: formatAttack(alert.alert_type),
        mitigation,
        path: formatPath(alert),
        readyToFreeze: attackCurve.readyToFreeze,
        throughputBeforeValue: attackCurve.before,
        detectionTime: formatMeasuredMilliseconds(detectionMs),
        responseTime: formatResponseTime(responseMs, mitigationInstalled),
        throughputBefore: formatThroughput(attackCurve.before, "No baseline"),
        throughputAfter: formatThroughput(attackCurve.after, "Collecting"),
        packetLoss: estimatePacketLoss(attackCurve),
        networkStability: stability.label,
        stabilityTone: stability.tone,
      };
    });
}

function mergeFrozenRows(currentRows, computedRows) {
  const currentBySignature = new Map(currentRows.map((row) => [row.signature, row]));

  return computedRows.map((computedRow) => {
    const frozenRow = currentBySignature.get(computedRow.signature);
    if (
      frozenRow &&
      computedRow.throughputBeforeValue !== null &&
      computedRow.throughputBeforeValue > (frozenRow.throughputBeforeValue || 0)
    ) {
      return computedRow;
    }
    if (isCompleteMetricRow(frozenRow)) {
      return frozenRow;
    }
    if (isCompleteMetricRow(computedRow)) {
      return computedRow;
    }
    return computedRow;
  });
}

function isCompleteMetricRow(row) {
  if (!row) {
    return false;
  }

  return (
    row.detectionTime !== "Collecting" &&
    row.responseTime !== "Pending rule stats" &&
    row.responseTime !== "Rule installed" &&
    row.throughputBefore !== "No baseline" &&
    row.throughputAfter !== "Collecting" &&
    row.readyToFreeze
  );
}

function estimateControllerDetectionMs(alert) {
  if (!alert.traffic_started_at || !alert.detected_at) {
    return null;
  }

  return secondsToMilliseconds(alert.detected_at - alert.traffic_started_at);
}

function estimateControllerMitigationMs(alert) {
  if (!alert.detected_at || !alert.rule_installed_at) {
    return null;
  }

  return secondsToMilliseconds(alert.rule_installed_at - alert.detected_at);
}

function dedupeAttackAlerts(alerts) {
  const attacksBySignature = new Map();

  alerts
    .filter((alert) =>
      ["single_source_flood", "multi_source_flood"].includes(alert.alert_type),
    )
    .forEach((alert) => {
      attacksBySignature.set(attackSignature(alert), alert);
    });

  return [...attacksBySignature.values()];
}

function attackSignature(alert) {
  return [
    alert.alert_type,
    alert.mitigation || inferMitigation(alert),
    alert.dst_ip || "victim",
    ...(alert.src_ips?.length ? [...alert.src_ips].sort() : [alert.src_ip || "multiple"]),
  ].join("|");
}

function analyzeAttackCurve(history, alertTime, threshold) {
  const alertMilliseconds = resolveAlertMilliseconds(history, alertTime);
  const window = filterWindow(history, alertMilliseconds, -15_000, 15_000);
  const latestPointMilliseconds = latestMilliseconds(window);
  const peakPoint = maxVictimPoint(window);
  const peakMilliseconds = peakPoint ? clockToMilliseconds(peakPoint.time) : null;

  if (!peakPoint || peakMilliseconds === null) {
    return { before: null, after: null, detectionMs: null, responseMs: null, readyToFreeze: false };
  }

  const peakBytes = Number(peakPoint.victim_throughput || 0);
  const attackStartPoint = findAttackStartPoint(window, peakMilliseconds, threshold, peakBytes);
  const protectedPoint = findPostPeakProtectedPoint(window, peakMilliseconds, threshold, peakBytes);
  const attackStartMilliseconds = attackStartPoint ? clockToMilliseconds(attackStartPoint.time) : null;
  const protectedMilliseconds = protectedPoint ? clockToMilliseconds(protectedPoint.time) : null;

  return {
    before: bytesToMbps(peakBytes),
    after: protectedPoint ? bytesToMbps(Number(protectedPoint.victim_throughput || 0)) : null,
    detectionMs:
      attackStartMilliseconds === null
        ? null
        : millisecondsBetween(attackStartMilliseconds, peakMilliseconds),
    responseMs:
      protectedMilliseconds === null
        ? null
        : millisecondsBetween(peakMilliseconds, protectedMilliseconds),
    readyToFreeze:
      protectedMilliseconds !== null &&
      latestPointMilliseconds !== null &&
      latestPointMilliseconds - protectedMilliseconds >= FREEZE_SETTLE_MS,
  };
}

function estimatePacketLoss({ before, after }) {
  if (before === null || after === null || before <= 0) {
    return "N/A";
  }

  const loss = Math.max(0, ((before - after) / before) * 100);
  return `${loss.toFixed(1)}%`;
}

function formatThroughput(value, fallback) {
  if (value === null) {
    return fallback;
  }

  return `${value} Mbps`;
}

function formatMeasuredMilliseconds(milliseconds) {
  if (milliseconds !== null) {
    return formatMilliseconds(milliseconds);
  }

  return "Collecting";
}

function formatResponseTime(milliseconds, mitigationInstalled) {
  if (milliseconds !== null && milliseconds > 0) {
    return `${formatMilliseconds(milliseconds)} installed`;
  }
  if (milliseconds === 0) {
    return "Same sample installed";
  }

  return mitigationInstalled ? "Rule installed" : "Pending rule stats";
}

function estimateStability(hosts, alert) {
  const affectedIps = new Set([
    alert.dst_ip,
    alert.src_ip,
    ...(alert.src_ips || []),
  ].filter(Boolean));
  const legitimateHosts = hosts.filter((host) => !affectedIps.has(host.ip));
  const impacted = legitimateHosts.filter((host) =>
    ["blocked", "rate_limited", "under_attack"].includes(host.status),
  ).length;

  if (impacted === 0) {
    return { label: "Stable", tone: "stable" };
  }

  return { label: `${impacted} host${impacted === 1 ? "" : "s"} impacted`, tone: "warning" };
}

function hasMatchingMitigation(alert, flows, meters) {
  if (alert.mitigation === "rate_limit") {
    return meters.length > 0 || flows.some((flow) => /meter[:=]\d+/i.test(flow.actions || ""));
  }

  const sources = [alert.src_ip, ...(alert.src_ips || [])].filter(Boolean);
  return flows.some((flow) => {
    const match = flow.match || "";
    const drops = (flow.actions || "").trim().toLowerCase() === "drop";
    return drops && sources.some((source) => match.includes(source));
  });
}

function maxVictimPoint(points) {
  if (!points.length) {
    return null;
  }

  return points.reduce((maxPoint, point) => {
    const throughput = Number(point.victim_throughput || 0);
    const maxThroughput = Number(maxPoint.victim_throughput || 0);
    return throughput > maxThroughput ? point : maxPoint;
  }, points[0]);
}

function latestMilliseconds(points) {
  const timestamps = points
    .map((point) => clockToMilliseconds(point.time))
    .filter((timestamp) => timestamp !== null);

  return timestamps.length ? Math.max(...timestamps) : null;
}

function findAttackStartPoint(points, peakMilliseconds, threshold, peakBytes) {
  const spikeFloor = peakBytes * 0.05;

  return points.find((point) => {
    const pointMilliseconds = clockToMilliseconds(point.time);
    if (pointMilliseconds === null || pointMilliseconds > peakMilliseconds) {
      return false;
    }
    return (
      Number(point.packet_rate || 0) >= threshold ||
      Number(point.victim_throughput || 0) >= spikeFloor
    );
  });
}

function findPostPeakProtectedPoint(points, peakMilliseconds, threshold, peakBytes) {
  const recoveredThroughput = peakBytes * 0.1;
  const mitigatedThroughput = peakBytes * 0.85;
  return points.find((point) => {
    const pointMilliseconds = clockToMilliseconds(point.time);
    if (pointMilliseconds === null || pointMilliseconds <= peakMilliseconds) {
      return false;
    }

    return (
      Number(point.victim_throughput || 0) <= recoveredThroughput ||
      Number(point.victim_throughput || 0) <= mitigatedThroughput ||
      Number(point.packet_rate || 0) < threshold
    );
  });
}

function filterWindow(history, anchorMilliseconds, minOffset, maxOffset) {
  if (anchorMilliseconds === null) {
    return [];
  }

  return history.filter((point) => {
    const pointMilliseconds = clockToMilliseconds(point.time);
    if (pointMilliseconds === null) {
      return false;
    }

    const offset = pointMilliseconds - anchorMilliseconds;
    return offset >= minOffset && offset <= maxOffset;
  });
}

function bytesToMbps(bytesPerSecond) {
  return Number(((bytesPerSecond * 8) / 1_000_000).toFixed(2));
}

function resolveAlertMilliseconds(history, alertTime) {
  const alertMilliseconds = clockToMilliseconds(alertTime);
  if (alertMilliseconds === null || typeof alertTime !== "string" || alertTime.includes(".")) {
    return alertMilliseconds;
  }

  const sameSecondPoint = history.find((point) => {
    const pointMilliseconds = clockToMilliseconds(point.time);
    return (
      pointMilliseconds !== null &&
      Math.floor(pointMilliseconds / 1000) === Math.floor(alertMilliseconds / 1000)
    );
  });

  return sameSecondPoint ? clockToMilliseconds(sameSecondPoint.time) : alertMilliseconds;
}

function millisecondsBetween(startMilliseconds, endMilliseconds) {
  let milliseconds = endMilliseconds - startMilliseconds;
  if (milliseconds < 0) {
    milliseconds += 24 * 60 * 60 * 1000;
  }
  return milliseconds;
}

function formatMilliseconds(milliseconds) {
  const safeMilliseconds = Math.max(0, milliseconds);
  if (safeMilliseconds < 10 && safeMilliseconds > 0) {
    return `${safeMilliseconds.toFixed(1)} ms`;
  }

  return `${Math.round(safeMilliseconds).toLocaleString()} ms`;
}

function secondsToMilliseconds(seconds) {
  return Math.max(0, seconds * 1000);
}

function formatAttack(type) {
  return type === "single_source_flood" ? "Single-source flood" : "Multi-source flood";
}

function formatPath(alert) {
  const sources = alert.src_ips?.length ? alert.src_ips.join(", ") : alert.src_ip || "multiple";
  return `${sources} -> ${alert.dst_ip || "victim"}`;
}

function inferMitigation(alert) {
  return alert.alert_type === "single_source_flood" ? "drop" : "rate_limit";
}

function clockToMilliseconds(clock) {
  if (typeof clock !== "string") {
    return null;
  }

  const [time, milliseconds = "0"] = clock.split(".");
  const parts = time.split(":").map(Number);
  if (parts.length !== 3 || parts.some((part) => Number.isNaN(part))) {
    return null;
  }

  const [hours, minutes, seconds] = parts;
  return (
    (hours * 60 * 60 + minutes * 60 + seconds) * 1000 +
    Number(milliseconds.padEnd(3, "0").slice(0, 3))
  );
}

export default EvaluationMetricsPanel;
