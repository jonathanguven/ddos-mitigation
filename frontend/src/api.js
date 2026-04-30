const API_BASE = import.meta.env.VITE_API_BASE_URL;

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
  meters: () => request("/api/meters"),
  startNormalTraffic: () =>
    request("/api/traffic/normal/start", { method: "POST" }),
  startSingleSourceFlood: () =>
    request("/api/demo/single-source-flood/start", { method: "POST" }),
  startMultiSourceFlood: () =>
    request("/api/demo/multi-source-flood/start", { method: "POST" }),
  stopTraffic: () => request("/api/traffic/stop", { method: "POST" }),
  resetDemo: () => request("/api/reset", { method: "POST" }),
  refreshFlows: () => request("/api/flows/refresh", { method: "POST" }),
};
