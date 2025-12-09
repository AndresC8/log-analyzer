import pandas as pd

def basic_metrics(df_logs: pd.DataFrame):
    total_events = len(df_logs)
    failed_logins = df_logs[df_logs["event_type"] == "login_failed"].shape[0]
    succesful_logins = df_logs[df_logs["event_type"] == "login_success"].shape[0]

    return {
        "total_events": total_events,
        "failed_logins": failed_logins,
        "succesful_logins": succesful_logins       
    }