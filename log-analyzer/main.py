from analyzer.loader import load_logs
from analyzer.detections import detect_bruteforce

def main():
    df = load_logs("auth_log_with_portscan.csv")
    alerts = detect_bruteforce(df)
    if alerts.empty:
        print("empty")
    else:
        print("Suspicious brute-force detctted")
        print(alerts)

if __name__  == "__main__":
    main()