
import time

WINDOW_SECONDS = 2
MODIFICATION_THRESHOLD = 10
RENAME_THRESHOLD = 10
BATCHES_PER_CLASS = 10


def detect(modifications, extension_renames):
    return (
        modifications >= MODIFICATION_THRESHOLD
        and extension_renames >= RENAME_THRESHOLD
    )


def replay_batch(label):
    modifications = 0
    extension_renames = 0

    # 20 ticks over 2 seconds = 10 ticks per second.
    # Each tick represents one modification.
    for _ in range(20):
        modifications += 1

        # Suspicious batches also have 10 renames per second.
        if label == "suspicious":
            extension_renames += 1

        time.sleep(WINDOW_SECONDS / 20)

    prediction = detect(modifications, extension_renames)

    print(
        f"Actual={label:10} "
        f"Modifications={modifications:2} "
        f"Extension renames={extension_renames:2} "
        f"Predicted={'suspicious' if prediction else 'benign'}"
    )

    return label, prediction


results = []

for _ in range(BATCHES_PER_CLASS):
    results.append(replay_batch("benign"))

for _ in range(BATCHES_PER_CLASS):
    results.append(replay_batch("suspicious"))

tp = sum(actual == "suspicious" and predicted
         for actual, predicted in results)
tn = sum(actual == "benign" and not predicted
         for actual, predicted in results)
fp = sum(actual == "benign" and predicted
         for actual, predicted in results)
fn = sum(actual == "suspicious" and not predicted
         for actual, predicted in results)

print("\n--- CONFUSION COUNTS ---")
print(f"True positives:  {tp}")
print(f"True negatives:  {tn}")
print(f"False positives: {fp}")
print(f"False negatives: {fn}")

total = len(results)
print(f"Accuracy: {(tp + tn) / total * 100:.1f}%")

if tn + fp:
    print(f"Specificity: {tn / (tn + fp) * 100:.1f}%")

if tp + fn:
    print(f"Recall: {(tp / (tp + fn)) * 100:.1f}%")
