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

function MetricsChart({ history }) {
  const data = (history.length ? history : [emptyPoint()]).map((point) => ({
    time: point.time,
    packets: point.packet_rate || 0,
    mbps: bytesToMbps(point.byte_rate || 0),
    victim: bytesToMbps(point.victim_throughput || 0),
  }));

  return (
    <section className="panel metrics-panel">
      <div className="panel-heading">
        <h2>Metrics</h2>
      </div>
      <div className="chart-wrap">
        <ResponsiveContainer width="100%" height={270}>
          <LineChart data={data} margin={{ top: 12, right: 20, left: 0, bottom: 10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#d7dde5" />
            <XAxis dataKey="time" tick={{ fontSize: 12 }} minTickGap={22} />
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
              name="packet rate"
            />
            <Line
              yAxisId="mbps"
              type="monotone"
              dataKey="mbps"
              stroke="#1f7a5a"
              strokeWidth={2}
              dot={false}
              name="byte rate"
            />
            <Line
              yAxisId="mbps"
              type="monotone"
              dataKey="victim"
              stroke="#2456a6"
              strokeWidth={2}
              dot={false}
              name="victim throughput"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}

function bytesToMbps(bytesPerSecond) {
  return Number(((bytesPerSecond * 8) / 1_000_000).toFixed(2));
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
