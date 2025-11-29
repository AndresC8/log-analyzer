import pandas as pd

def detect_bruteforce(df: pd.DataFrame, threshold=5):
    failed = df[df["event_type"] == "login_failed"]
    failed_ips = failed.groupby("source_ip").size().reset_index(name="failures")
    suspicious = failed_ips[failed_ips["failures"] >= threshold]
    return suspicious

def detect_succesful_bruteforce(df: pd.DataFrame, threshold: int =5):
    failed = df[df["event_type"] == "login_failed"]
    failed_ips = failed.groupby("source_ip").size().reset_index(name="failures")
    
    success = df[df["event_type"] == "login_success"]
    success_ips = set(success["source_ip"])

    suspicious = (
        failed_ips[(failed_ips["failures"] >= threshold ) & (failed_ips["source_ip"].isin(success_ips))]
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

def detect_password_spraying(
    df: pd.DataFrame,
    min_total_failures: int = 20,
    min_distinct_user: int = 5,
    max_failures_per_user: int = 3
    ):

    df = df.copy()
    
    failed = df[df["event_type"] == "login_failed"]

    failed_by_ip = (
        failed
        .groupby(["source_ip", "username"])
        .size()
        .reset_index(name="failed_per_user")
        )

    ip_group = failed_by_ip.groupby("source_ip")

    total_failures = ip_group["failed_per_user"].sum()
    distinct_users = ip_group["username"].nunique()
    max_failures = ip_group["failed_per_user"].max()

    ip_stats = pd.DataFrame(
        {
            "source_ip": total_failures.index,
            "total_failures": total_failures.values,
            "distinct_user": distinct_users.values,
            "max_failures_per_user": max_failures.values,
        }
    )

    suspicious = ip_stats[
        (ip_stats["total_failures"] >= min_total_failures )
        & 
        (ip_stats["distinct_user"]>= min_distinct_user) 
        & 
        (ip_stats["max_failures_per_user"] <= max_failures_per_user)
    ]
    

    return suspicious
