from analyzer.loader import load_logs

def main():
    df = load_logs("auth_log_With_portscan.csv")
    print(df.head())



if __name__  == "__main__":
    main()