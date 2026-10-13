
import shutil
import subprocess


def timeshift_available():
    return shutil.which("timeshift") is not None


def list_snapshots():
    if not timeshift_available():
        return False, "Timeshift is not installed or not in PATH."

    try:
        result = subprocess.run(
            ["pkexec", "timeshift", "--list"],
            capture_output=True,
            text=True,
            timeout=60
        )#

        output = result.stdout.strip()
        error = result.stderr.strip()

        if result.returncode == 0:
            return True, output or "No snapshot information returned."

        return False, error or output or "Could not list snapshots."

    except subprocess.TimeoutExpired:
        return False, "Timeshift timed out."
    except FileNotFoundError:
        return False, "pkexec is missing. Install polkit."
    except Exception as exc:
        return False, str(exc)


def create_snapshot(comment="CERBERUS manual snapshot"):
    if not timeshift_available():
        return False, "Timeshift is not installed or not in PATH."

    try:
        result = subprocess.run(
            [
                "pkexec",
                "timeshift",
                "--create",
                "--comments",
                comment,
                "--tags",
                "O"
            ],
            capture_output=True,
            text=True,
            timeout=600
        )

        output = result.stdout.strip()
        error = result.stderr.strip()

        if result.returncode == 0:
            return True, output or "Snapshot command completed."

        return False, error or output or "Snapshot creation failed."

    except subprocess.TimeoutExpired:
        return False, "Snapshot creation timed out."
    except FileNotFoundError:
        return False, "pkexec is missing. Install polkit."
    except Exception as exc:
        return False, str(exc)
