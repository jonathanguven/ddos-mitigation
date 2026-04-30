const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://172.16.64.133:8000";

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    throw new Error(`API ${response.status}: ${path}`);
  }

  return response.json();
}

export const api = {
  health: () => request("/api/health"),
  status: () => request("/api/status"),
  stats: () => request("/api/stats"),
  alerts: () => request("/api/alerts"),
  flows: () => request("/api/flows"),
  startNormalTraffic: () =>
    request("/api/traffic/normal/start", { method: "POST" }),
  startAttackTraffic: () =>
    request("/api/traffic/attack/start", { method: "POST" }),
  stopTraffic: () => request("/api/traffic/stop", { method: "POST" }),
  resetDemo: () => request("/api/reset", { method: "POST" }),
  refreshFlows: () => request("/api/flows/refresh", { method: "POST" }),
};
