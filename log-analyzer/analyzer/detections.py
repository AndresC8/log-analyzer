import pandas as pd

def detect_bruteforce(df: pd.DataFrame, threshold: int = 5):
    failed_ips = df[df["event_type"] == "login_failed"]
    failed_by_ips = (
        failed_ips
        .groupby('source_ip')
        .size()
        .reset_index(name="failures")
        )
    suspicious = failed_by_ips[failed_by_ips["failures"] >= threshold]
    return suspicious
 