
import json
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent


def generate_incident_summary():

    report_path = ROOT / "hdfs_anomaly_report.json"

    with open(report_path, "r", encoding="utf-8") as file:
        anomalies = json.load(file)

    if not anomalies:
        return {
            "total": 0,
            "severity": {},
            "block_ids": [],
            "message": "No anomalies detected.",
            "recommendation": "Continue monitoring HDFS logs."
        }

    severity_counts = Counter(
        item.get("severity", "UNKNOWN")
        for item in anomalies
    )

    block_ids = []

    for item in anomalies:
        message = item.get("message", "")

        for word in message.split():
            if word.startswith("blk_"):
                block_ids.append(word.rstrip(":,."))

    total = len(anomalies)

    summary_message = (
        f"{total} warning events were identified in the HDFS dataset. "
        "These events contain block-serving exceptions. "
        "They require investigation and do not independently "
        "confirm a cyberattack."
    )

    recommendation = (
        "Review the affected block IDs, inspect DataNode logs, "
        "and investigate possible network or block-transfer issues."
    )

    return {
        "total": total,
        "severity": dict(severity_counts),
        "block_ids": sorted(set(block_ids)),
        "message": summary_message,
        "recommendation": recommendation
    }
