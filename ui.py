import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import subprocess
import threading
import sys

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("TLS File Sender")
        self.geometry("750x520")

        self.process = None

        # =====================
        # MODE
        # =====================
        self.mode = ctk.CTkSegmentedButton(
            self,
            values=["client", "server"]
        )
        self.mode.set("client")
        self.mode.pack(pady=10)

        # =====================
        # CONNECTION FRAME
        # =====================
        frame = ctk.CTkFrame(self)
        frame.pack(pady=10, fill="x", padx=10)

        self.host = ctk.CTkEntry(frame, placeholder_text="Host")
        self.host.insert(0, "127.0.0.1")
        self.host.pack(side="left", padx=5)

        self.port = ctk.CTkEntry(frame, placeholder_text="Port", width=80)
        self.port.insert(0, "5001")
        self.port.pack(side="left", padx=5)

        # =====================
        # BUTTONS
        # =====================
        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(pady=10)

        ctk.CTkButton(btn_frame, text="Start", command=self.start).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Stop", command=self.stop).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Send File", command=self.send_file).pack(side="left", padx=5)

        # =====================
        # LOG BOX
        # =====================
        self.log = ctk.CTkTextbox(self, width=700, height=350)
        self.log.pack(padx=10, pady=10)

    def write(self, msg):
        self.log.insert("end", msg + "\n")
        self.log.see("end")

    def start(self):
        cmd = [
            sys.executable,
            "cli.py",
            "--mode", self.mode.get(),
            "--host", self.host.get(),
            "--port", self.port.get()
        ]

        self.write("[START] " + " ".join(cmd))

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        threading.Thread(target=self.read_output, daemon=True).start()

    def read_output(self):
        for line in self.process.stdout:
            self.write(line.strip())

    def stop(self):
        if self.process:
            self.process.terminate()
            self.write("[STOPPED]")
            self.process = None

    def send_file(self):
        if self.mode.get() != "client":
            self.write("Switch to client mode first")
            return

        file = filedialog.askopenfilename()
        if not file:
            return

        self.write(f"[FILE] {file}")

        proc = subprocess.Popen(
            [sys.executable, "cli.py", "--mode", "client", "--host", self.host.get(), "--port", self.port.get()],
            stdin=subprocess.PIPE,
            text=True
        )

        proc.stdin.write(file + "\nexit\n")
        proc.stdin.flush()
        proc.stdin.close()


if __name__ == "__main__":
    app = App()
    app.mainloop() 
