"""Validate saved calibration before changing any live threshold."""
import json
import logging

FLOORS = {"port_scan": 5, "flood_pps": 20, "suspicious_port": 3}
CEILINGS = {"port_scan": 200, "flood_pps": 5000, "suspicious_port": 100}


def load_thresholds(path):
    if not path.exists():
        return {}
    try:
        values = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(values, dict):
            raise ValueError("expected an object")
        for key in FLOORS:
            value = values[key]
            if type(value) is not int or not FLOORS[key] <= value <= CEILINGS[key]:
                raise ValueError(f"{key} must be an integer in "
                                 f"[{FLOORS[key]}, {CEILINGS[key]}]")
        return values
    except (OSError, ValueError, KeyError, TypeError) as exc:
        logging.getLogger("packetwatch.config").warning(
            "Ignoring invalid calibration %s; using all stock thresholds: %s", path, exc)
        return {}
