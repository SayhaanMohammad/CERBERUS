# SENTINEL — Ransomware Behaviour Monitor (prototype)

A small educational Python/Tkinter project that watches a chosen directory and applies explainable heuristics to file-system events.

## Requirements

- Python 3.10+
- Tkinter (often included with Python; on some Linux distributions install the system `tk` package)
- `watchdog`

## Run on Linux

```bash
cd ransomware-monitor
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

If Tkinter is missing on Arch Linux, install the `tk` package using pacman.

## Safe testing

1. Start by monitoring the included `test_files` folder.
2. Create and edit a few disposable text files inside it.
3. For a batch test, create multiple dummy files manually or with a harmless test script.
4. Review the live table and `logs/alerts.log`.

Do not monitor your whole home directory or system directories for this class prototype. Use disposable files only.

## False-positive configuration

Open Settings in the app. Patterns are matched against a source/destination path or basename. Keep patterns narrow. A matching pattern is labelled as expected/reviewed in the UI, but it is not proof that an operation is safe. The prototype still calculates the behaviour score internally.

## Limitations

- This is an educational heuristic prototype, not a production anti-ransomware product.
- `watchdog` reports file-system events but does not reliably identify the process responsible for each event.
- Event counts, thresholds and risk scores need to be tuned against benign and suspicious test cases.
- The monitor does not stop processes, restore files, or prevent writes.
- File-system events may be coalesced or reported differently depending on OS and filesystem.
