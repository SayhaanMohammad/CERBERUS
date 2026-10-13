
from pathlib import Path
import time

folder = Path.home() / "CERBERUS/test_files/end_to_end"
files = sorted(folder.glob("document_*.txt"))

if len(files) < 10:
    raise SystemExit(
        "Not enough test files. Create the 20 test files first."
    )

print(f"Testing CERBERUS on {len(files)} disposable files...")

for file in files:
    # Simulate repeated file modifications.
    with file.open("a") as f:
        f.write("Harmless simulated activity\n")

    # Simulate a suspicious extension-changing rename.
    renamed = file.with_suffix(".locked-test")
    file.rename(renamed)

    print(f"Modified and renamed: {file.name}")
    time.sleep(0.05)

print("Simulation complete. No files were encrypted or deleted.")
