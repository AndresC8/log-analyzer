from analyzer.loader import load_logs
from analyzer.detections import detect_portscan

def main():
    df = load_logs("auth_log_with_portscan.csv")
    print(detect_portscan(df))

if __name__  == "__main__":
    main()