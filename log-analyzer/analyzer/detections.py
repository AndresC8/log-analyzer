import pandas as pd

def detect_bruteforce(df: pd.DataFrame, threshold: int = 5):
    failed = df[df["event_type"] == "login_failed"]
    failed_ips = failed.groupby("source_ip").size().reset_index(name="failures")

    success = df[df["event_type"] == "login_success"]
    success_ips = set(success["source_ip"])

    suspicious = (
        failed_ips[(failed_ips["failures"] >= threshold) 
                             & 
                             (failed_ips["source_ip"].isin(success_ips))]
                             )

    return suspicious

def detect_portscan(df: pd.DataFrame, threshold: int = 5):
    port_probe = df[df["event_type"] == "port_probe"]
    mask = (
        port_probe
        .groupby('source_ip')
        .size()
        .reset_index(name="portscan")
    )
    suspicious = mask[mask["portscan"] >= threshold]
    return suspicious

def detect_rarelogin(
        df: pd.DataFrame,
        night_start: int = 0,
        night_end: int = 5
    ):
    df = df.copy()

    df["hour"] = df["timestamp"].dt.hour
    
    success = df[df["event_type"] == "login_success"]
    suspicious = success[(success["hour"] >= night_start) & (success["hour"] <= night_end) ]
    
    return suspicious

    
    
