import pandas as pd

def detect_bruteforce(df: pd.DataFrame, threshold=5):

    """
    Detect IPs with repeated failed login attempts.

    An IP is considered suspicious if it has at least `threshold`
    events with event_type == "login_failed".

    Returns
    -------
    pd.DataFrame
        DataFrame with columns like: source_ip, failures.
    """

    failed = df[df["event_type"] == "login_failed"]
    failed_ips = failed.groupby("source_ip").size().reset_index(name="failures")
    suspicious = failed_ips[failed_ips["failures"] >= threshold]
    return suspicious

def detect_succesful_bruteforce(df: pd.DataFrame, threshold: int =5):

    """
    Detect IPs that show brute force attempts followed by at least one successful login

    An IP is considered suspicious if:
    - it has at least `threshold` failed logins, and
    - it also appears with event_type == "loginm_success"

    Returns
    pd.DataFrame
        DataFrame with columns like: source_ip, failures etc
    """

    failed = df[df["event_type"] == "login_failed"]
    failed_ips = failed.groupby("source_ip").size().reset_index(name="failures")
    
    success = df[df["event_type"] == "login_success"]
    success_ips = set(success["source_ip"])

    suspicious = (
        failed_ips[(failed_ips["failures"] >= threshold ) & (failed_ips["source_ip"].isin(success_ips))]
    )

    return suspicious

def detect_portscan(df: pd.DataFrame, threshold: int = 5):

    """
    Detect basic port scanning activity by counting port_probe events per source_ip.

    Return

    pd.DataFrame
        DataFrame with columns like: source_ip, portscan
    """

    port_probe = df[df["event_type"] == "port_probe"]
    mask = (
        port_probe
        .groupby('source_ip')
        .size()
        .reset_index(name="portscan")
    )
    suspicious = mask[mask["portscan"] >= threshold]
    return suspicious

def detect_offhours(
        df: pd.DataFrame,
        night_start: int = 0,
        night_end: int = 5
    ):

    """
    Detect successful logins that occur during off-hours.

    Parameters

    night_start : int
        Lower bound (inclusive both) of the suspicious hour range (0–23)
    night_end : int
        Upper bound (inclusive both) of the suspicious hour range (0–23)

    Returns

    pd.DataFrame
        Subset of df with login_success events in the specified hour range
    """

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

    """
    Detect password spraying patterns from a single source IP.

    A source_ip is considered suspicious if:
    - It has at least `min_total_failures` failed logins in total.
    - It has attacked at least `min_distinct_users` different usernames.
    - It has no more than "max_failures_per_user" failures for any single username,
      which differentiates spraying from classic brute force.

    Returns

    pd.DataFrame
        DataFrame with columns:
        - source_ip
        - total_failures
        - distinct_users
        - max_failures_per_user
    """
    
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
