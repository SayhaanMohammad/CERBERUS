import queue
import tkinter as tk
from gui import RansomwareMonitorApp


def main():
    event_queue = queue.Queue()
    root = tk.Tk()
    RansomwareMonitorApp(root, event_queue)
    root.mainloop()


if __name__ == "__main__":
    main()
