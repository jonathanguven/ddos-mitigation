import { useMemo, useState } from "react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const CHART_WINDOW_SECONDS = 60;

function MetricsChart({ history }) {
  const [frozenHistory, setFrozenHistory] = useState(null);
  const isFrozen = frozenHistory !== null;
  const chartHistory = isFrozen ? frozenHistory : history;
  const visibleHistory = useMemo(
    () => filterRecentHistory(chartHistory, CHART_WINDOW_SECONDS),
    [chartHistory],
  );
  const data = (visibleHistory.length ? visibleHistory : [emptyPoint()]).map((point) => ({
    time: point.time,
    packets: point.packet_rate || 0,
    mbps: bytesToMbps(point.byte_rate || 0),
    victim: bytesToMbps(point.victim_throughput || 0),
  }));

  return (
    <section className="panel metrics-panel">
      <div className="panel-heading">
        <h2>Metrics</h2>
        <div className="metrics-heading-actions">
          <span className={`panel-meta ${isFrozen ? "metrics-paused" : ""}`}>
            {isFrozen ? "Frozen view" : "Live - last 1 min"}
          </span>
          <button className="metrics-freeze-toggle" onClick={toggleFrozen} type="button">
            {isFrozen ? "Resume" : "Pause"}
          </button>
        </div>
      </div>
      <div className="chart-wrap">
        <ResponsiveContainer width="100%" height={270}>
          <LineChart data={data} margin={{ top: 12, right: 20, left: 0, bottom: 10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#d7dde5" />
            <XAxis
              dataKey="time"
              tick={{ fontSize: 12 }}
              minTickGap={22}
              tickFormatter={formatTickTime}
            />
            <YAxis
              yAxisId="packets"
              tick={{ fontSize: 12 }}
              width={56}
              label={{ value: "pkt/s", angle: -90, position: "insideLeft" }}
            />
            <YAxis
              yAxisId="mbps"
              orientation="right"
              tick={{ fontSize: 12 }}
              width={56}
              label={{ value: "Mbps", angle: 90, position: "insideRight" }}
            />
            <Tooltip formatter={(value) => Number(value).toLocaleString()} />
            <Legend />
            <Line
              yAxisId="packets"
              type="monotone"
              dataKey="packets"
              stroke="#d23b3b"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
              name="packet rate"
            />
            <Line
              yAxisId="mbps"
              type="monotone"
              dataKey="mbps"
              stroke="#1f7a5a"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
              name="byte rate"
            />
            <Line
              yAxisId="mbps"
              type="monotone"
              dataKey="victim"
              stroke="#2456a6"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
              name="victim throughput"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  );

  function toggleFrozen() {
    if (isFrozen) {
      setFrozenHistory(null);
      return;
    }

    setFrozenHistory([...(history || [])]);
  }
}

function filterRecentHistory(history, windowSeconds) {
  if (!history.length) {
    return [];
  }

  const latestSeconds = clockToSeconds(history[history.length - 1].time);
  if (latestSeconds === null) {
    return history.slice(-30);
  }

  return history.filter((point) => {
    const pointSeconds = clockToSeconds(point.time);
    if (pointSeconds === null) {
      return false;
    }

    let ageSeconds = latestSeconds - pointSeconds;
    if (ageSeconds < 0) {
      ageSeconds += 24 * 60 * 60;
    }

    return ageSeconds <= windowSeconds;
  });
}

function clockToSeconds(clock) {
  if (typeof clock !== "string") {
    return null;
  }

  const parts = clock.split(":").map(Number);
  if (parts.length !== 3 || parts.some((part) => Number.isNaN(part))) {
    return null;
  }

  const [hours, minutes, seconds] = parts;
  return hours * 60 * 60 + minutes * 60 + seconds;
}

function bytesToMbps(bytesPerSecond) {
  return Number(((bytesPerSecond * 8) / 1_000_000).toFixed(2));
}

function formatTickTime(clock) {
  return typeof clock === "string" ? clock.split(".")[0] : clock;
}

function emptyPoint() {
  return {
    time: "--:--:--",
    packet_rate: 0,
    byte_rate: 0,
    victim_throughput: 0,
  };
}

export default MetricsChart;
