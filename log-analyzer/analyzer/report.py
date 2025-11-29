from __future__ import annotations

from pathlib import Path
from datetime import datetime
from typing import Mapping

import pandas as pd

SECTION_TITLES: dict[str, str] = {
    "bruteforce": "Brute Force Attempts",
    "successful_bruteforce": "Successful Brute Force",
    "portscan": "Port Scan Activity",
    "offhours": "Off-hours Logins",
    "password_spraying": "Password Spraying",
}


def _format_section(name: str, df: pd.DataFrame) -> list[str]:
    title = SECTION_TITLES.get(name, name.replace("_", " ").title())
    lines: list[str] = []

    lines.append(f"== {title} ==")

    if df is None:
        lines.append("No data provided for this detection.")
        return lines

    if df.empty:
        lines.append("No suspicious activity detected.")
        return lines

    lines.append(f"{len(df)} suspicious record(s) detected.")
    lines.append("")  

    lines.append(df.to_string(index=False))

    return lines


def generate_report(
    results: Mapping[str, pd.DataFrame],
    output_file: Path | str,
) -> Path:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []

    lines.append("=" * 30)
    lines.append("LOG ANALYSIS REPORT")
    lines.append("=" * 30)
    lines.append(
        f"Generated at: {datetime.utcnow().isoformat(timespec='seconds')}Z (UTC)"
    )
    lines.append("")

    handled_keys: set[str] = set()

    for key in SECTION_TITLES:
        if key in results:
            lines.append("")  
            section_lines = _format_section(key, results[key])
            lines.extend(section_lines)
            handled_keys.add(key)

    for key, df in results.items():
        if key in handled_keys:
            continue
        lines.append("")
        section_lines = _format_section(key, df)
        lines.extend(section_lines)

    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path
