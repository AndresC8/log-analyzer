from analyzer.report import generate_report
from analyzer.log_analyzer import LogAnalyzer
from analyzer.paths import RAW_DIR

def main():
    log_file = "auth_log_with_portscan.csv"
    try:
        print(f"[#] Loading logs from {log_file}")
        analyzer = LogAnalyzer.from_csv(log_file)
        
        if analyzer.df.empty:
            print("[x] Loaded DataFrame is empty")
        
        print("[#] running detections")
        results = analyzer.run_all_detections()
        
        report_path = generate_report(results, output_file="reports/log_analysis_report.txt",)
        print(f"[#] Report generated at: {report_path}")

    except FileNotFoundError:
        print(f"[x] logfile not found {log_file}")
    except Exception as exc:
        print(f"[x] Unexpected error while analyzing logs: {exc}")
        
if __name__  == "__main__":
    main()