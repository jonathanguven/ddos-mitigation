from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import mininet_manager
import ryu_client
import state_store
import traffic_manager


app = FastAPI(title="SDN IDS + DDoS Mitigation Demo API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/status")
def status():
    try:
        state = ryu_client.get("/ryu/status")
    except ryu_client.RyuUnavailable:
        state = state_store.get_status()
    state["ryu_running"] = bool(state.get("ryu_running")) or mininet_manager.ryu_running()
    state["mininet_running"] = bool(state.get("mininet_running")) or mininet_manager.mininet_running()
    return state


@app.post("/api/traffic/normal/start")
def start_normal_traffic():
    return traffic_manager.start_normal()


@app.post("/api/demo/single-source-flood/start")
def start_single_source_flood():
    return traffic_manager.start_single_source_flood()


@app.post("/api/demo/multi-source-flood/start")
def start_multi_source_flood():
    return traffic_manager.start_multi_source_flood()


@app.post("/api/traffic/stop")
def stop_traffic():
    return traffic_manager.stop_traffic()


@app.post("/api/reset")
def reset_demo():
    return traffic_manager.reset_demo()


@app.get("/api/stats")
def stats():
    try:
        return ryu_client.get("/ryu/stats")
    except ryu_client.RyuUnavailable:
        return state_store.get_stats()


@app.get("/api/alerts")
def alerts():
    try:
        ryu_alerts = ryu_client.get("/ryu/alerts")
    except ryu_client.RyuUnavailable:
        return state_store.get_alerts()

    fallback_alerts = state_store.get_alerts().get("alerts", [])
    alerts = merge_attack_alerts([*fallback_alerts, *ryu_alerts.get("alerts", [])])[-100:]
    return {"alerts": alerts}


def merge_attack_alerts(alerts):
    merged = {}
    passthrough = []
    for alert in alerts:
        signature = attack_signature(alert)
        if signature is None:
            passthrough.append(alert)
            continue
        current = merged.get(signature, {})
        merged[signature] = {**current, **alert}
        if current.get("traffic_started_at") and not alert.get("traffic_started_at"):
            merged[signature]["traffic_started_at"] = current["traffic_started_at"]
    return [*passthrough, *merged.values()]


def attack_signature(alert):
    alert_type = alert.get("alert_type")
    if alert_type not in {"single_source_flood", "multi_source_flood"}:
        return None
    sources = alert.get("src_ips") or [alert.get("src_ip") or "multiple"]
    return "|".join(
        [
            alert_type,
            alert.get("dst_ip") or "victim",
            *sorted(str(source) for source in sources),
        ]
    )


@app.get("/api/flows")
def flows():
    try:
        return ryu_client.get("/ryu/flows")
    except ryu_client.RyuUnavailable as exc:
        return {"flows": [], "raw": [], "error": ryu_client.fallback_error(exc)}


@app.get("/api/meters")
def meters():
    try:
        return ryu_client.get("/ryu/meters")
    except ryu_client.RyuUnavailable as exc:
        return {"meters": [], "raw": [], "error": ryu_client.fallback_error(exc)}


@app.post("/api/flows/refresh")
def refresh_flows():
    return flows()
