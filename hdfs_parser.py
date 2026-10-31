
import re
import json
from collections import Counter


def parse_hdfs_line(line):
    pattern = r"^(\d{6})\s+(\d{6})\s+(\d+)\s+(\w+)\s+(.*)$"

    match = re.match(pattern, line.strip())

    if not match:
        return None

    date, time, number, level, message = match.groups()

    return {
        "date": date,
        "time": time,
        "number": int(number),
        "level": level,
        "message": message
    }


# Severity Classification
def classify_severity(log):
    message = log["message"].lower()

    if "got exception while serving" in message:
        return "MEDIUM"

    return "LOW"


if __name__ == "__main__":

    file_path = "dataset/hdfs/HDFS_2k.log"

    total_logs = 0
    log_levels = Counter()
    event_types = Counter()
    warning_logs = []
    anomaly_logs = []

    with open(file_path, "r", encoding="utf-8") as file:

        for line in file:

            result = parse_hdfs_line(line)

            if result:
                total_logs += 1
                log_levels[result["level"]] += 1

                if result["level"] == "WARN":
                    warning_logs.append(result)

                    if "Got exception while serving" in result["message"]:

                        anomaly_logs.append({
                            "date": result["date"],
                            "time": result["time"],
                            "message": result["message"],
                            "severity": classify_severity(result),
                            "status": "Requires Investigation"
                        })

                event_type = result["message"].split(":")[0]
                event_types[event_type] += 1

    # Save Anomaly Report
    with open("hdfs_anomaly_report.json", "w", encoding="utf-8") as file:
        json.dump(anomaly_logs, file, indent=4)

    print("\nAnomaly report saved successfully!")

    # Dataset Analysis
    print("\n===== HDFS DATASET ANALYSIS =====")
    print("Total parsed logs:", total_logs)

    print("\nLog Level Counts:")
    for level, count in log_levels.items():
        print(level, ":", count)

    print("\nTop 10 Event Types:")
    for event, count in event_types.most_common(10):
        print(event, ":", count)

    # Warning Summary
    print("\n===== HDFS WARN LOGS =====")
    print("Total warnings:", len(warning_logs))

    # Anomaly Summary
    print("\n===== ANOMALY SUMMARY =====")
    print("Total Logs:", total_logs)
    print("Total Warnings:", len(warning_logs))
    print("Total Anomalies:", len(anomaly_logs))

    if len(anomaly_logs) > 0:
        print("Status: Requires Investigation")
    else:
        print("Status: No Matching Anomalies Found")

    # Anomaly Report
    print("\n===== HDFS ANOMALY REPORT =====")

    for log in anomaly_logs[:10]:
        print("Date:", log["date"])
        print("Time:", log["time"])
        print("Severity:", log["severity"])
        print("Status:", log["status"])
        print("Reason:", log["message"])
        print("-----------------------------")
