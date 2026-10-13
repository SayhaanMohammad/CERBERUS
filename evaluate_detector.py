
import time
from detector import BehaviourDetector

WINDOW_SECONDS = 2
MODIFICATION_THRESHOLD = 10
RENAME_THRESHOLD = 10
BATCHES_PER_CLASS = 10


def replay_batch(label):
    detector = BehaviourDetector(
        window_seconds=WINDOW_SECONDS,
        file_threshold=MODIFICATION_THRESHOLD,
    )

    # Send modifications at the same rate for both classes.
    for i in range(20):
        detector.analyze_event({
            "event_type": "modified",
            "src_path": f"batch_{label}_{i}.txt",
        })
        time.sleep(WINDOW_SECONDS / 20)

    score = 0
    reasons = []

    # Suspicious batches additionally contain extension-changing renames.
    if label == "suspicious":
        for i in range(RENAME_THRESHOLD):
            score, reasons = detector.analyze_event({
                "event_type": "moved",
                "src_path": f"rename_{i}.txt",
                "dest_path": f"rename_{i}.testlock",
            })

    prediction = score >= 4

    return {
        "actual": label,
        "predicted": "suspicious" if prediction else "benign",
        "score": score,
        "modifications": 20,
        "extension_renames": (
            RENAME_THRESHOLD if label == "suspicious" else 0
        ),
        "passed": (
            (label == "suspicious" and prediction)
            or (label == "benign" and not prediction)
        ),
        "reasons": reasons,
    }


def run_c1_evaluation(progress_callback=None):
    results = []
    total = BATCHES_PER_CLASS * 2

    for label in ("benign", "suspicious"):
        for index in range(BATCHES_PER_CLASS):
            result = replay_batch(label)
            results.append(result)

            if progress_callback:
                progress_callback(index + 1, BATCHES_PER_CLASS, label)

    tp = sum(
        r["actual"] == "suspicious" and r["predicted"] == "suspicious"
        for r in results
    )
    tn = sum(
        r["actual"] == "benign" and r["predicted"] == "benign"
        for r in results
    )
    fp = sum(
        r["actual"] == "benign" and r["predicted"] == "suspicious"
        for r in results
    )
    fn = sum(
        r["actual"] == "suspicious" and r["predicted"] == "benign"
        for r in results
    )

    accuracy = (tp + tn) / total * 100
    specificity = tn / (tn + fp) * 100 if tn + fp else 0
    recall = tp / (tp + fn) * 100 if tp + fn else 0

    return {
        "results": results,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "specificity": specificity,
        "recall": recall,
    }


if __name__ == "__main__":
    report = run_c1_evaluation()

    for result in report["results"]:
        print(
            f"Actual={result['actual']:10} "
            f"Predicted={result['predicted']:10} "
            f"Score={result['score']}"
        )

    print("\n--- C1 CONFUSION COUNTS ---")
    print(f"True positives:  {report['tp']}")
    print(f"True negatives:  {report['tn']}")
    print(f"False positives: {report['fp']}")
    print(f"False negatives: {report['fn']}")
    print(f"Accuracy: {report['accuracy']:.1f}%")
    print(f"Specificity: {report['specificity']:.1f}%")
    print(f"Recall: {report['recall']:.1f}%")
