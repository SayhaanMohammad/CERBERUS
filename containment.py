
def decide_response(suspicious, responsible_pid, trusted_pids):
    """
    Decide whether CERBERUS may automatically contain a process.

    This prototype never terminates processes.
    """
    if not suspicious:
        return {
            "alert": False,
            "terminate": False,
            "reason": "No suspicious pattern detected."
        }

    # Suspicious activity must still generate an alert.
    if responsible_pid is None:
        return {
            "alert": True,
            "terminate": False,
            "reason": (
                "Suspicious behaviour detected, but the responsible "
                "PID is unknown. Automatic termination refused."
            )
        }

    # Never terminate a process identified as trusted.
    if responsible_pid in trusted_pids:
        return {
            "alert": True,
            "terminate": False,
            "reason": (
                "Suspicious behaviour detected, but the PID is "
                "marked trusted. Automatic termination refused "
                "pending investigation."
            )
        }

    # Conservative prototype policy: no automatic termination.
    return {
        "alert": True,
        "terminate": False,
        "reason": (
            "Suspicious behaviour detected. Manual investigation "
            "is required; automatic termination is disabled."
        )
    }

