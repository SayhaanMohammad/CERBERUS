import os
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from alerts import send_alert
from detector import BehaviourDetector
from false_positive import load_config, save_config, check_false_positive
from monitor import start_monitor
from timeshift_manager import list_snapshots, create_snapshot
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from containment import decide_response
from evaluate_detector import run_c1_evaluation
class RansomwareMonitorApp:
    def __init__(self, root, event_queue):
        self.root = root
        self.event_queue = event_queue
        self.config = load_config()
        self.detector = BehaviourDetector(
            window_seconds=int(self.config["window_seconds"]),
            file_threshold=int(self.config["file_threshold"]),
        )
        self.observer = None
        self.monitor_path = os.path.abspath(self.config["monitor_directory"])
        os.makedirs(self.monitor_path, exist_ok=True)
        os.makedirs("logs", exist_ok=True)

        self.total_events = 0
        self.suspicious_events = 0
        self.filtered_events = 0

        self.root.title("CERBERUS | Ransomware Behaviour Monitor")
        self.root.geometry("1040x680")
        self.root.minsize(820, 540)
        self.root.configure(bg="#0A0A0A")

        self._configure_style()
        self._build_ui()
        self._set_status("Stopped", "#9CA3AF")
        self.root.after(150, self._process_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    
    def _run_c1_evaluation(self):
        self.c1_results.configure(
            text="Running C1 replay evaluation... please wait."
        )

        def worker():
            try:
                report = run_c1_evaluation()
                self.root.after(
                    0,
                    lambda: self._show_c1_batch_results(report["results"])
                )
                text = (
                    f"TP: {report['tp']}  |  TN: {report['tn']}  |  "
                    f"FP: {report['fp']}  |  FN: {report['fn']}  |  "
                    f"Accuracy: {report['accuracy']:.1f}%  |  "
                    f"Specificity: {report['specificity']:.1f}%"
                )
                status = "PASS" if (
                    report["tp"] == 10
                    and report["tn"] == 10
                    and report["fp"] == 0
                    and report["fn"] == 0
                ) else "REVIEW"

                self.root.after(
                    0,
                    lambda: self.c1_results.configure(
                        text=f"{status} — {text}"
                    )
                )
            except Exception as exc:
                self.root.after(
                    0,
                    lambda: self.c1_results.configure(
                        text=f"Evaluation failed: {exc}"
                    )
                )

        threading.Thread(target=worker, daemon=True).start()

        

    def _configure_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#0A0A0A", foreground="#E5E7EB",
                        fieldbackground="#0A0A0A", rowheight=27, borderwidth=0)
        style.configure("Treeview.Heading", background="#0A0A0A", foreground="#F9FAFB",
                        font=("TkDefaultFont", 10, "bold"))
        style.map("Treeview", background=[("selected", "#374151")],
                  foreground=[("selected", "#FFFFFF")])
        style.configure("TCombobox", fieldbackground="#1F2937", background="#374151",
                        foreground="#F9FAFB")

    def _build_ui(self):

        # C1 evaluation panel
        c1_frame = tk.Frame(
            self.root, bg="#151515", padx=14, pady=10
        )
        c1_frame.pack(fill="x", padx=20, pady=(0, 12))

        tk.Label(
            c1_frame,
            text="C1 | MATCHED BEHAVIOUR EVALUATION",
            bg="#151515",
            fg="#FF6666",
            font=("TkDefaultFont", 10, "bold")
        ).pack(anchor="w")

        tk.Label(
            c1_frame,
            text="Simulated replay using the CERBERUS BehaviourDetector",
            bg="#151515",
            fg="#D1D5DB"
        ).pack(anchor="w", pady=(4, 6))

        self.c1_results = tk.Label(
            c1_frame,
            text="Not run yet | TP: —  TN: —  FP: —  FN: —",
            bg="#151515",
            fg="#F9FAFB",
            anchor="w"
        )
        self.c1_results.pack(fill="x", pady=4)

        tk.Button(
            c1_frame,
            text="Run C1 Evaluation",
            command=self._run_c1_evaluation,
            bg="#0F766E",
            fg="#FFFFFF",
            relief="flat",
            padx=12,
            pady=6
        ).pack(anchor="e")

        # Individual C1 batch results
        c1_table_frame = tk.Frame(c1_frame, bg="#151515")
        c1_table_frame.pack(fill="x", pady=(10, 0))

        self.c1_table_frame = c1_table_frame
        self.c1_table_visible = True

        tk.Button(
            c1_frame,
            text="Hide batch results",
            command=self._toggle_c1_table,
            bg="#0A0A0A",
            fg="#FF6666",
            relief="flat",
        ).pack(anchor="w", pady=(5, 0))

        c1_columns = (
            "batch", "actual", "predicted",
            "modifications", "renames", "result"
        )

        self.c1_table = ttk.Treeview(
            c1_table_frame,
            columns=c1_columns,
            show="headings",
            height=6
        )

        c1_headings = {
            "batch": "BATCH",
            "actual": "ACTUAL",
            "predicted": "PREDICTED",
            "modifications": "MODIFICATIONS",
            "renames": "EXTENSION RENAMES",
            "result": "RESULT",
        }

        for col, heading in c1_headings.items():
            self.c1_table.heading(col, text=heading)
            self.c1_table.column(col, width=130, anchor="center")

        c1_scrollbar = ttk.Scrollbar(
            c1_table_frame,
            orient="vertical",
            command=self.c1_table.yview
        )
        self.c1_table.configure(yscrollcommand=c1_scrollbar.set)

        self.c1_table.pack(side="left", fill="both", expand=True)
        c1_scrollbar.pack(side="right", fill="y")

        c1_scrollbar.pack(side="right", fill="y")
        self.c1_table.configure(yscrollcommand=c1_scrollbar.set)
        self.c1_table.tag_configure("pass", foreground="#5EEAD4")
        self.c1_table.tag_configure("fail", foreground="#FCA5A5")


        top = tk.Frame(self.root, bg="#0A0A0A", padx=22, pady=18)
        top.pack(fill="x")
        tk.Label(top, text="◈  CERBERUS", font=("TkDefaultFont", 21, "bold"),
                 fg="#FF6666", bg="#0A0A0A").pack(side="left")
        tk.Label(top, text="RANSOMWARE BEHAVIOUR MONITOR",
                 font=("TkDefaultFont", 10), fg="#FF6666", bg="#0A0A0A").pack(
                     side="left", padx=14, pady=(7, 0))
        self.status_label = tk.Label(top, text="● STOPPED", font=("TkDefaultFont", 10, "bold"),
                                     fg="#FF6666", bg="#0A0A0A")
        self.status_label.pack(side="right", pady=6)

        path_frame = tk.Frame(self.root, bg="#0A0A0A", padx=14, pady=12)
        path_frame.pack(fill="x", padx=20)
        tk.Label(path_frame, text="MONITOR DIRECTORY", fg="#FF6666",
                 bg="#0A0A0A", font=("TkDefaultFont", 9, "bold")).pack(anchor="w")
        path_row = tk.Frame(path_frame, bg="#0A0A0A")
        path_row.pack(fill="x", pady=(6, 0))
        self.path_var = tk.StringVar(value=self.monitor_path)
        tk.Entry(path_row, textvariable=self.path_var, bg="#0A0A0A", fg="#FF6666",
                 insertbackground="#FF6666", relief="flat").pack(side="left", fill="x", expand=True, ipady=7)
        self.browse_button = tk.Button(path_row, text="Browse", command=self._browse,
                                       bg="#0A0A0A", fg="#FF6666", relief="flat", padx=14)
        self.browse_button.pack(side="left", padx=(8, 0), ipady=4)
        self.start_button = tk.Button(path_row, text="▶  Start monitoring",
                                      command=self.start, bg="#0A0A0A", fg="#FF6666",
                                      activebackground="#115E59", relief="flat", padx=14)
        self.start_button.pack(side="left", padx=(8, 0), ipady=4)
        self.stop_button = tk.Button(path_row, text="■  Stop",
                                     command=self.stop, bg="#0A0A0A", fg="#FF6666",
                                     relief="flat", padx=14, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0), ipady=4)

        cards = tk.Frame(self.root, bg="#0A0A0A")
        cards.pack(fill="x", padx=20, pady=14)
        self.card_values = {}
        for key, label in [
            ("events", "FILE EVENTS"), ("suspicious", "SUSPICIOUS"),
            ("filtered", "EXPECTED / IGNORED"), ("risk", "LATEST RISK")
        ]:
            card = tk.Frame(cards, bg="#0A0A0A", padx=15, pady=12)
            card.pack(side="left", fill="x", expand=True, padx=(0, 10))
            tk.Label(card, text=label, bg="#0A0A0A", fg="#9CA3AF",
                     font=("TkDefaultFont", 9, "bold")).pack(anchor="w")
            value = tk.Label(card, text="0", bg="#0A0A0A", fg="#F9FAFB",
                             font=("TkDefaultFont", 22, "bold"))
            value.pack(anchor="w", pady=(5, 0))
            self.card_values[key] = value

        # Timeshift snapshot panel
        backup_frame = tk.Frame(
            self.root,
            bg="#151515",
            padx=14,
            pady=10
        )
        backup_frame.pack(fill="x", padx=20, pady=(0, 12))

        tk.Label(
            backup_frame,
            text="SYSTEM RECOVERY | TIMESHIFT",
            bg="#151515",
            fg="#FF6666",
            font=("TkDefaultFont", 10, "bold")
        ).pack(anchor="w")

        button_row = tk.Frame(backup_frame, bg="#151515")
        button_row.pack(fill="x", pady=(8, 5))

        tk.Button(
            button_row,
            text="↻ Refresh snapshots",
            command=self._refresh_timeshift,
            bg="#0A0A0A",
            fg="#FF6666",
            activebackground="#252525",
            activeforeground="#FFFFFF",
            relief="flat",
            padx=12,
            pady=6
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            button_row,
            text="+ Create manual snapshot",
            command=self._create_timeshift_snapshot,
            bg="#7F1D1D",
            fg="#FFFFFF",
            activebackground="#991B1B",
            activeforeground="#FFFFFF",
            relief="flat",
            padx=12,
            pady=6
        ).pack(side="left")

        self.timeshift_status = tk.Label(
            backup_frame,
            text="Ready — refresh to check available snapshots.",
            bg="#151515",
            fg="#D1D5DB",
            anchor="w"
        )
        self.timeshift_status.pack(fill="x", pady=(3, 5))

        self.timeshift_output = tk.Text(
            backup_frame,
            height=3,
            bg="#0A0A0A",
            fg="#D1D5DB",
            insertbackground="#FFFFFF",
            relief="flat",
            wrap="word",
            font=("TkFixedFont", 9)
        )
        self.timeshift_output.pack(fill="x")
        self.timeshift_output.insert(
            "1.0",
            "Timeshift output will appear here."
        )
        self.timeshift_output.configure(state="disabled")

        toolbar = tk.Frame(self.root, bg="#0A0A0A", padx=20)
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="LIVE FILE ACTIVITY", bg="#0A0A0A", fg="#FF6666",
                 font=("TkDefaultFont", 11, "bold")).pack(side="left")
        tk.Button(toolbar, text="Clear view", command=self._clear_view,
                  bg="#0A0A0A", fg="#FF6666", relief="flat", padx=10).pack(side="right")
        tk.Button(toolbar, text="Settings", command=self._settings,
                  bg="#0A0A0A", fg="#FF6666", relief="flat", padx=10).pack(side="right", padx=8)

        table_frame = tk.Frame(self.root, bg="#0A0A0A")
        table_frame.pack(fill="both", expand=True, padx=20, pady=(8, 8))
        columns = ("time", "event", "file", "risk", "details")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings")
        headings = {"time": "TIME", "event": "EVENT", "file": "FILE",
                    "risk": "RISK", "details": "ANALYSIS"}
        widths = {"time": 145, "event": 100, "file": 260, "risk": 90, "details": 300}
        for col in columns:
            self.table.heading(col, text=headings[col])
            self.table.column(col, width=widths[col], minwidth=70, stretch=(col in ("file", "details")))
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.table.tag_configure("high", foreground="#FCA5A5")
        self.table.tag_configure("medium", foreground="#FCD34D")
        self.table.tag_configure("normal", foreground="#A7F3D0")

        footer = tk.Label(self.root,
            text="Prototype only • Heuristic alerts can be wrong • Monitor a disposable test folder",
            bg="#0A0A0A", fg="#6B7280", font=("TkDefaultFont", 9), pady=8)
        footer.pack(fill="x")

    def _set_status(self, text, color):
        self.status_label.configure(text=f"● {text.upper()}", fg=color)

    def _browse(self):
        chosen = filedialog.askdirectory(title="Choose a directory to monitor")
        if chosen:
            self.path_var.set(chosen)

    def start(self):
        if self.observer and self.observer.is_alive():
            return
        path = os.path.abspath(os.path.expanduser(self.path_var.get().strip()))
        if not path or not os.path.isdir(path):
            messagebox.showerror("Invalid directory", "Choose an existing directory.")
            return
        self.monitor_path = path
        self.detector = BehaviourDetector(
            window_seconds=int(self.config["window_seconds"]),
            file_threshold=int(self.config["file_threshold"]),
        )
        try:
            self.observer = start_monitor(
                path,
                self.event_queue.put,
                ignore_paths=[os.path.abspath("logs")])
        except Exception as exc:
            self.observer = None
            messagebox.showerror("Could not start monitor", str(exc))
            return
        self.config["monitor_directory"] = path
        save_config(self.config)
        self._set_status("Monitoring", "#5EEAD4")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.path_var.set(path)

    def stop(self):
        observer = self.observer
        self.observer = None
        if observer:
            observer.stop()
            # Join briefly so the GUI does not hang while stopping.
            threading.Thread(target=observer.join, daemon=True).start()
        self._set_status("Stopped", "#9CA3AF")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def _process_queue(self):
        try:
            while True:
                event = self.event_queue.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        self.root.after(150, self._process_queue)

    def _handle_event(self, event):
        self.total_events += 1
        self.card_values["events"].configure(text=str(self.total_events))

        is_expected, explanation = check_false_positive(event, self.config)
        score, reasons = self.detector.analyze_event(event)
        if score >= 4:
            reasons.insert(0, "C1 detection triggered")

        # Expected-pattern matches can lower concern, but never hide a high-risk score.

        if score >= 4:
            self.suspicious_events += 1
            self.card_values["suspicious"].configure(
                text=str(self.suspicious_events)
            )
            self.card_values["risk"].configure(
                text=f"{score}/7", fg="#FCA5A5"
            )

    # Check whether the responsible process is known.
            responsible_pid = event.get("pid")

            response = decide_response(
                suspicious=True,
                responsible_pid=responsible_pid,
                trusted_pids=set()
            )

    # Include containment information in the existing alert.
            alert_reasons = list(reasons) if reasons else []
            pid_text = (
                str(responsible_pid)
                if responsible_pid is not None
                else "Unknown"
            )

            alert_reasons.append(f"Responsible PID: {pid_text}")
            alert_reasons.append(response["reason"])

            line = send_alert("HIGH RISK", score, alert_reasons)

            details = "; ".join(reasons) or "High risk score"
            details += f"; Responsible PID: {pid_text}"
            details += f"; {response['reason']}"

            risk_label = "HIGH"
            tag = "high"

        elif is_expected:
            self.filtered_events += 1
            self.card_values["filtered"].configure(text=str(self.filtered_events))
            risk_label = "REVIEW"
            details = explanation
            tag = "medium"
        elif score >= 2:
            self.suspicious_events += 1
            self.card_values["suspicious"].configure(text=str(self.suspicious_events))
            self.card_values["risk"].configure(text=f"{score}/7", fg="#FCD34D")
            details = "; ".join(reasons) or "Suspicious activity"
            risk_label = "MEDIUM"
            tag = "medium"
            send_alert("SUSPICIOUS", score, reasons)
        else:
            details = "No current heuristic threshold crossed"
            risk_label = "LOW"
            tag = "normal"
            self.card_values["risk"].configure(text=f"{score}/7", fg="#A7F3D0")

        shown_path = event.get("dest_path") or event.get("src_path") or ""
        try:
            shown_path = os.path.relpath(shown_path, self.monitor_path)
        except ValueError:
            pass
        self.table.insert("", 0, values=(
            event.get("timestamp", ""),
            event.get("event_type", ""),
            shown_path,
            risk_label,
            details
        ), tags=(tag,))
        # Keep the visible table bounded during long sessions.
        children = self.table.get_children()
        for item in children[500:]:
            self.table.delete(item)

    def _set_timeshift_output(self, message):
        self.timeshift_output.configure(state="normal")
        self.timeshift_output.delete("1.0", "end")
        self.timeshift_output.insert("1.0", message)
        self.timeshift_output.configure(state="disabled")

    def _refresh_timeshift(self):
        self.timeshift_status.configure(
            text="Checking Timeshift snapshots...",
            fg="#FCD34D"
        )
        threading.Thread(
            target=self._timeshift_worker,
            args=("list",),
            daemon=True
        ).start()

    def _create_timeshift_snapshot(self):
        confirmed = messagebox.askyesno(
            "Create system snapshot",
            "Request a manual Timeshift snapshot?\n\n"
            "This may require administrator authentication "
            "and take some time.",
            parent=self.root
        )

        if not confirmed:
            return

        self.timeshift_status.configure(
            text="Creating snapshot... Please wait.",
            fg="#FCD34D"
        )

        threading.Thread(
            target=self._timeshift_worker,
            args=("create",),
            daemon=True
        ).start()

    def _timeshift_worker(self, action):
        # Run the potentially slow Timeshift command off the GUI thread.
        if action == "list":
            success, output = list_snapshots()
        else:
            success, output = create_snapshot(
                "CERBERUS manual recovery snapshot"
            )

        # Tkinter widgets must be updated on the GUI thread.
        self.root.after(
            0,
            lambda: self._timeshift_finished(action, success, output)
        )

    def _timeshift_finished(self, action, success, output):
        if success:
            status = (
                "Snapshot list refreshed."
                if action == "list"
                else "Snapshot command completed."
            )
            self.timeshift_status.configure(
                text=status,
                fg="#5EEAD4"
            )
        else:
            self.timeshift_status.configure(
                text="Timeshift operation failed.",
                fg="#FF6666"
            )

        self._set_timeshift_output(output)

        # Refresh the list after a successful snapshot request.
        if action == "create" and success:
            self.root.after(500, self._refresh_timeshift)


    def _clear_view(self):
        for item in self.table.get_children():
            self.table.delete(item)

    def _settings(self):
        win = tk.Toplevel(self.root)
        win.title("Detection Settings")
        win.configure(bg="#0A0A0A")
        win.resizable(False, False)
        frame = tk.Frame(win, bg="#0A0A0A", padx=18, pady=18)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="Detection thresholds", bg="#0A0A0A", fg="#F9FAFB",
                 font=("TkDefaultFont", 13, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 14))
        window_var = tk.StringVar(value=str(self.config["window_seconds"]))
        threshold_var = tk.StringVar(value=str(self.config["file_threshold"]))
        ignore_var = tk.StringVar(value=", ".join(self.config.get("ignore_patterns", [])))
        expected_var = tk.StringVar(value=", ".join(self.config.get("expected_activity_patterns", [])))

        fields = [
            ("Time window (seconds)", window_var),
            ("Distinct-file threshold", threshold_var),
            ("Ignore path patterns (comma-separated)", ignore_var),
            ("Expected activity patterns (comma-separated)", expected_var),
        ]
        for row, (label, variable) in enumerate(fields, start=1):
            tk.Label(frame, text=label, bg="#0A0A0A", fg="#D1D5DB").grid(
                row=row, column=0, sticky="w", pady=6, padx=(0, 12))
            tk.Entry(frame, textvariable=variable, bg="#0A0A0A", fg="#F9FAFB",
                     insertbackground="white", relief="flat", width=34).grid(
                row=row, column=1, sticky="ew", pady=6, ipady=5)

        tk.Label(frame, text="Patterns match filenames or full paths. Use narrowly scoped patterns.",
                 bg="#0A0A0A", fg="#9CA3AF", wraplength=440, justify="left").grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(8, 12))

        def save():
            try:
                seconds = int(window_var.get())
                threshold = int(threshold_var.get())
                if seconds < 1 or threshold < 2:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Invalid settings", "Window must be >= 1 second and threshold >= 2.", parent=win)
                return
            self.config["window_seconds"] = seconds
            self.config["file_threshold"] = threshold
            self.config["ignore_patterns"] = [x.strip() for x in ignore_var.get().split(",") if x.strip()]
            self.config["expected_activity_patterns"] = [x.strip() for x in expected_var.get().split(",") if x.strip()]
            save_config(self.config)
            self.detector = BehaviourDetector(window_seconds=seconds, file_threshold=threshold)
            win.destroy()
            messagebox.showinfo("Settings saved", "Settings saved. Stop and restart monitoring to apply them.", parent=self.root)

        tk.Button(frame, text="Save settings", command=save, bg="#0F766E", fg="#FF6666",
                  relief="flat", padx=14, pady=7).grid(row=6, column=1, sticky="e", pady=(8, 0))

    def _toggle_c1_table(self):
        if self.c1_table_visible:
            self.c1_table_frame.pack_forget()
            self.c1_table_visible = False
        else:
            self.c1_table_frame.pack(fill="x", pady=(10, 0))
            self.c1_table_visible = True


    def _on_close(self):
        self.stop()
        self.root.destroy()

    
    def _show_c1_batch_results(self, results):
        for item in self.c1_table.get_children():
            self.c1_table.delete(item)

        for index, result in enumerate(results, start=1):
            passed = result["passed"]

            self.c1_table.insert(
                "",
                "end",
                values=(
                    index,
                    result["actual"].upper(),
                    result["predicted"].upper(),
                    result["modifications"],
                    result["extension_renames"],
                    "TRUE POSITIVE" if result["actual"] == "suspicious" and passed
                    else "TRUE NEGATIVE" if result["actual"] == "benign" and passed
                    else "FALSE POSITIVE" if result["actual"] == "benign"
                    else "FALSE NEGATIVE"
                ),
                tags=("pass" if passed else "fail",)
            )
        children = self.c1_table.get_children()
        if children:
            self.c1_table.see(children[0])

