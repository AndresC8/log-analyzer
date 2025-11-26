import pandas as pd
import os
import datetime
from datetime import timedelta

DATA_DIR = "data"
RAW_DIR = os.path.join(DATA_DIR, "raw")

def load_logs(filename: str):
    path = os.path.join(RAW_DIR, filename)

    if not os.path.exists(path):
        raise FileNotFoundError(f"Doesnt exists: {path}")
    print(f"Loading logs from: {path}")
    df = pd.read_csv(path) 

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    return df   

def detect_bruteforce(df: pd.DataFrame, treshold: int = 5):
    failed = df[df["event_type"] == "login_failed"]

    if failed.empty:
        print("Empty")
        return pd.DataFrame()
    
    counts = (
        failed.groupby("source_ip")
        .size()
        .reset_index(name="failures")
    )

    suspicius = counts[counts["failures"] >= treshold]
    return suspicius

def detect_port_scan(df, threshold=5):

    probes = df[
        df["event_type"].str.contains("probe|scan", case=False, na=False)
    ]

    if probes.empty:
        return pd.DataFrame()  


    grouped = (
        probes.groupby(["source_ip", "host"])
        .size()
        .reset_index(name="count")
    )

    alerts = grouped[grouped["count"] >= threshold]

    return alerts
    
def main():
    df = load_logs("auth_log_with_portscan.csv")
    
    alerts = detect_port_scan(df, threshold=5)

    if alerts.empty:
        print("No port scan detected")
    else:
        print("\nSuspicious port scan detected\n")
        print(alerts)

if __name__ == "__main__":
    main()
