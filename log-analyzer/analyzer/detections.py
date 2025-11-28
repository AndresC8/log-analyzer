import pandas as pd

def detect_bruteforce(df: pd.DataFrame, threshold: int = 5):
    failed_ips = df[df["event_type"] == "login_failed"]
    mask = (
        failed_ips
        .groupby('source_ip')
        .size()
        .reset_index(name="failures")
        )
    suspicious = mask[mask["failures"] >= threshold]
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