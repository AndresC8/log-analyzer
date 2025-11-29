from .loader import load_logs, clean_logs
from pathlib import Path
import pandas as pd
from .detections import (
    detect_bruteforce,
    detect_password_spraying,
    detect_portscan,
    detect_offhours,
    detect_succesful_bruteforce
)


class LogAnalyzer:

    #Run multiple detections

    def __init__(self, df: pd.DataFrame):
        self.df = df
        
    @classmethod
    def from_csv(cls, filename: str | Path):

        filename  = Path(filename)
        df = load_logs(filename)
        df = clean_logs(df)
        return cls(df)
    
    def run_bruteforce_detection(self, threshold: int = 5):
        return detect_bruteforce(self.df,threshold=threshold)
    
    def run_offhours_detection(self, night_start: int = 0, night_end: int = 5):
        return detect_offhours(self.df, night_start=night_start, night_end=night_end)
    
    def run_succesful_bruteforce_detection(self, threshold: int = 5):
        return detect_succesful_bruteforce(self.df, threshold=threshold)
    
    def run_portscan_detection(self, threshold: int = 5):
        return detect_portscan(self.df, threshold=threshold)
    
    def run_password_spraying_detection(
            self,
            min_total_failures: int = 20,
            min_distinct_user: int = 5,
            max_failures_per_user: int = 3,
    ):
    
        return detect_password_spraying(
            self.df,
            min_total_failures=min_total_failures,
            min_distinct_user=min_distinct_user,
            max_failures_per_user=max_failures_per_user
        )
    
    def run_all_detections(self):

        # Run all available detections and return a dict of DataFrames
        
        return {
            "bruteforce": self.run_bruteforce_detection(),
            "succesful_bruteforce": self.run_succesful_bruteforce_detection(),
            "portscan": self.run_portscan_detection(),
            "offhours": self.run_offhours_detection(),
            "password_spraying": self.run_password_spraying_detection(),
        }