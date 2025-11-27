from .loader import load_logs

class LogAnalyzer:
    def __init__(self, filename: str):
        self.filename = filename
        self.df = load_logs(filename)
        pass