
from pathlib import Path
import time

# Keep all test activity inside Cerberus's disposable test folder.
BASE = Path(__file__).resolve().parent / "test_files"
TEST = BASE / "c1_simulation"
TEST.mkdir(parents=True, exist_ok=True)

def prepare_files():
    for i in range(20):
        (TEST / f"modify_{i:02}.txt").write_text("Initial test data\n")
        (TEST / f"rename_{i:02}.txt").write_text("Harmless test data\n")

def run_batch(suspicious):
    label = "SUSPICIOUS" if suspicious else "BENIGN"
    print(f"\nStarting {label} batch: 2 seconds")

    # Give the GUI time to settle before the batch.
    time.sleep(1)
    start = time.monotonic()

    for i in range(20):
        # One modification per 0.1-second interval.
        p = TEST / f"modify_{i:02}.txt"
        p.write_text(f"Harmless modification {i} at {time.time()}\n")

        if suspicious:
            # One extension rename per interval.
            old = TEST / f"rename_{i:02}.txt"
            new = TEST / f"rename_{i:02}.testlock"
            old.rename(new)

        # Maintain approximately 10 iterations per second.
        target = start + (i + 1) * 0.1
        delay = target - time.monotonic()
        if delay > 0:
            time.sleep(delay)

    elapsed = time.monotonic() - start
    print(f"{label} batch finished in {elapsed:.2f}s")
    print("Check Cerberus's File Events, Latest Risk and Live File Activity.")

if __name__ == "__main__":
    prepare_files()

    print(f"Test directory: {TEST}")
    print("Files prepared. Check that Cerberus is monitoring this folder.")
    input("Press Enter to run the BENIGN batch... ")
    run_batch(suspicious=False)

    input("\nWait at least 11 seconds, then press Enter for SUSPICIOUS... ")
    run_batch(suspicious=True)

    print("\nSimulation complete. No personal files were targeted.")
