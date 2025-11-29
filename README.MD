# Log Analyzer

Small Python project to analyze authentication logs and detect suspicious activity using pandas.
I made this to practice data handling, simple SOC-style detections, and organizing a cleaner project structure.

## What it detects

- Brute force attempts (many `login_failed`)
- Successful brute force (failures + `login_success`)
- Port scanning (`port_probe`)
- Off-hours logins
- Password spraying (one IP targeting many users)

## How to use

Install pandas:

```
pip install pandas
```

Run:

```
python main.py
```

This loads the CSV in `data/raw/`, runs all detections, and generates a report at:

```
reports/log_analysis_report.txt
```

## Project structure

```
analyzer/
  loader.py
  detections.py
  log_analyzer.py
  report.py
data/raw/
main.py
reports/
```

## Notes

This is a personal learning project to practice pandas and basic SOC-style detections.
I plan to keep improving it (better portscan logic, CLI, JSON output, etc.).
