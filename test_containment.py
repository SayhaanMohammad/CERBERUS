
from containment import decide_response

# One unrelated trusted process is running.
trusted_pids = {4242}

# A suspicious batch was detected, but the event source
# cannot identify which process caused it.
suspicious = True
responsible_pid = None

result = decide_response(
    suspicious=suspicious,
    responsible_pid=responsible_pid,
    trusted_pids=trusted_pids
)

print("=== CERBERUS CONTAINMENT TEST ===")
print("Suspicious pattern: detected")
print("Responsible PID: unknown")
print("Unrelated trusted PID: 4242")
print("Alert raised:", result["alert"])
print("Automatic termination:", result["terminate"])
print("Decision:", result["reason"])

assert result["alert"] is True
assert result["terminate"] is False

print("\nPASS: alert raised; termination refused.")
