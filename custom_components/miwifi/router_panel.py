"""Verified router telemetry for the experimental, on-demand status panel."""
from __future__ import annotations

import math

from .router_dump import async_collect_reads

MODELS = {"rc01": "BE10000", "rc06": "BE7000"}
def model_of(updater) -> str:
    data = updater.data or {}
    return str(data.get("model") or str(data.get("device_model", "")).split(".")[-1]).lower()


def _number(value):
    if isinstance(value, bool):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def _flag(value):
    return True if value in (1, "1") else False if value in (0, "0") else None


def panel_metrics(reads: list[dict]) -> dict:
    """Project only understood fields; never expose raw API configuration."""
    responses = {r["id"]: r["response"] for r in reads
                 if r.get("outcome") == "ok" and isinstance(r.get("response"), dict)}
    metrics = {}
    thermal = responses.get("thermal_control", {})
    for section, key, output in (("temp", "curr", "temperature"), ("fan", "speed", "fan_speed")):
        value = thermal.get(section)
        number = _number(value.get(key)) if isinstance(value, dict) else None
        if number is not None:
            metrics[output] = number
    if "multiwan_basic" in responses:
        info = responses["multiwan_basic"].get("info")
        if isinstance(info, dict):
            metrics["multiwan"] = _flag(info.get("enable"))
    mode = responses.get("mesh_backhaul_preference", {}).get("bhmode")
    if mode in ("auto", "wired", "wireless"):
        metrics["backhaul"] = mode
    thresholds = responses.get("mesh_steering", {}).get("roaming_rssi_thr")
    if isinstance(thresholds, dict):
        metrics["roaming"] = {key: value for key in ("2g", "5g", "5gh")
                              if (value := _number(thresholds.get(key))) is not None}
    for source, key, output in (("wps_info", "wps_enable", "wps"), ("nfc_info", "nfc_enable", "nfc")):
        if source in responses:
            metrics[output] = _flag(responses[source].get(key))
    ports = responses.get("port_map", {}).get("ports")
    if isinstance(ports, list):
        metrics["ports"] = [{key: str(port[key])[:64] for key in ("label", "speed", "service")
                             if isinstance(port.get(key), (str, int))} for port in ports[:16]
                            if isinstance(port, dict)]
    return metrics


async def async_panel_reads(updaters: list) -> list[dict]:
    selected = [updater for updater in updaters if model_of(updater) in MODELS]
    if not selected:
        return []
    report = await async_collect_reads(selected, {"router_specific": True}, {})
    return [{"model": model_of(updater), "metrics": panel_metrics(router["requests"]),
             "failed": [r["id"] for r in router["requests"] if r.get("outcome") in ("error", "timeout", "truncated")]}
            for updater, router in zip(selected, report["routers"])]
