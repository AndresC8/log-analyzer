import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
RAW_DIR = os.path.join(DATA_DIR, "raw")

if __name__ == "__main__":
    print("BASE_DIR:    ", BASE_DIR)
    print("PROJECT_ROOT:", PROJECT_ROOT)
    print("DATA_DIR:    ", DATA_DIR)
    print("RAW_DIR:     ", RAW_DIR)
