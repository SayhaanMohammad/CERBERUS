
from detector import BehaviourDetector

detector = BehaviourDetector(window_seconds=2, file_threshold=10)

# First, verify that modifications alone do NOT trigger C1.
for i in range(10):
    score, reasons = detector.analyze_event({
        "event_type": "modified",
        "src_path": f"file{i}.txt",
    })

print("Modifications only:", score, reasons)
assert score == 0

# Now send 10 extension-changing renames.
for i in range(10):
    score, reasons = detector.analyze_event({
        "event_type": "moved",
        "src_path": f"file{i}.txt",
        "dest_path": f"file{i}.testlock",
    })

print("Both signals:", score, reasons)
assert score == 5, "C1 did not trigger as expected"

print("PASS: C1 requires both signals.")
