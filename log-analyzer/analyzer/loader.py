import os 
import pandas as pd
from .paths import RAW_DIR

SUPPORTED_EXT = {".csv", ".log", ".txt", ".json"}

def load_logs(filename: str):
    path = os.path.join(RAW_DIR, filename)

    if not os.path.exists(path):
        raise FileNotFoundError(f"Does not exists: {path}")

    print(f"Loading logs from {path}")
    df = _read_raw_file(path)
    df = clean_logs(path)

    return df

def _read_raw_file(path: str):
    _, ext = os.path.splitext(path)
    ext = ext.lower()

    if ext not in SUPPORTED_EXT:
        raise ValueError(f"Unsupported file extension: {ext} Supported: {SUPPORTED_EXT}")
    
    if ext == ".csv":
        return pd.read_csv(path)
    
    if ext in {".log", ".txt"}:
        return pd.read_csv(path)

    if ext == ".json":
        return pd.read_json(path)

    raise ValueError(f"Unhandled extension: {ext}")

def clean_logs(df: pd.DataFrame):
    df = df.copy()
    df.columns = [c.strip().lower() for c in df.columns]

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])

    for col in df.select_dtypes(include=["object"]).columns:
        df[col] = df[col].astype(str).str.strip()

    required_cols = {"event_type", "source_ip"}
    missing = required_cols - set(df.columns)
    if missing:
        print(f"Missing expected columns: {required_cols}")

    df = df.drop_duplicates()

    return df 