from datetime import datetime
import os


def send_alert(level, score, reasons, log_dir="logs"):
    os.makedirs(log_dir, exist_ok=True)
    message = " | ".join(reasons) if reasons else "Behaviour score exceeded threshold"
    line = f"{datetime.now().isoformat(timespec='seconds')} [{level}] score={score} | {message}"
    with open(os.path.join(log_dir, "alerts.log"), "a", encoding="utf-8") as file:
        file.write(line + "\n")
    return line
