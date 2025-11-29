from analyzer.report import generate_report
from analyzer.log_analyzer import LogAnalyzer
from analyzer.paths import RAW_DIR



def main():
    log_file = "auth_log_with_portscan.csv"

    analyzer = LogAnalyzer.from_csv(log_file)

    results = analyzer.run_all_detections()

    report_path = generate_report(results, output_file="reports/log_analysis_report.txt",)
    

    print(f"\nReport generated at: {report_path}")


if __name__  == "__main__":
    main()