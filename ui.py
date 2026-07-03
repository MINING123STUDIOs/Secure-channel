import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading
import subprocess
import sys
import os

# =========================
# 🌸 GUI APP
# =========================

class TLSFileGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("TLS File Sender GUI")
        self.root.geometry("700x500")

        self.process = None

        # =========================
        # MODE SELECT
        # =========================
        self.mode_var = tk.StringVar(value="client")

        frame_top = tk.Frame(root)
        frame_top.pack(pady=10)

        tk.Radiobutton(frame_top, text="Client", variable=self.mode_var, value="client").pack(side=tk.LEFT)
        tk.Radiobutton(frame_top, text="Server", variable=self.mode_var, value="server").pack(side=tk.LEFT)

        # =========================
        # CONNECTION SETTINGS
        # =========================
        frame_conn = tk.Frame(root)
        frame_conn.pack(pady=5)

        tk.Label(frame_conn, text="Host:").grid(row=0, column=0)
        self.host_entry = tk.Entry(frame_conn)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.grid(row=0, column=1)

        tk.Label(frame_conn, text="Port:").grid(row=0, column=2)
        self.port_entry = tk.Entry(frame_conn)
        self.port_entry.insert(0, "5001")
        self.port_entry.grid(row=0, column=3)

        # =========================
        # CERT SETTINGS (server only relevant)
        # =========================
        frame_cert = tk.Frame(root)
        frame_cert.pack(pady=5)

        tk.Label(frame_cert, text="Cert:").grid(row=0, column=0)
        self.cert_entry = tk.Entry(frame_cert, width=25)
        self.cert_entry.insert(0, "cert.pem")
        self.cert_entry.grid(row=0, column=1)

        tk.Label(frame_cert, text="Key:").grid(row=0, column=2)
        self.key_entry = tk.Entry(frame_cert, width=25)
        self.key_entry.insert(0, "key.pem")
        self.key_entry.grid(row=0, column=3)

        # =========================
        # CONTROLS
        # =========================
        frame_btn = tk.Frame(root)
        frame_btn.pack(pady=10)

        self.start_btn = tk.Button(frame_btn, text="Start", command=self.start)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(frame_btn, text="Stop", command=self.stop)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.send_file_btn = tk.Button(frame_btn, text="Send File", command=self.send_file)
        self.send_file_btn.pack(side=tk.LEFT, padx=5)

        # =========================
        # LOG OUTPUT
        # =========================
        self.log_box = scrolledtext.ScrolledText(root, height=20)
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # =========================
    # 🧾 LOGGING
    # =========================
    def log(self, msg):
        self.log_box.insert(tk.END, msg + "\n")
        self.log_box.see(tk.END)

    # =========================
    # 🚀 START SERVER/CLIENT
    # =========================
    def start(self):
        mode = self.mode_var.get()
        host = self.host_entry.get()
        port = self.port_entry.get()

        cert = self.cert_entry.get()
        key = self.key_entry.get()

        cmd = [sys.executable, "cli.py", "--mode", mode, "--host", host, "--port", port]

        if mode == "server":
            cmd += ["--cert", cert, "--key", key]

        self.log(f"[STARTING] {' '.join(cmd)}")

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        threading.Thread(target=self.read_output, daemon=True).start()

    # =========================
    # 📡 READ CLI OUTPUT
    # =========================
    def read_output(self):
        if not self.process:
            return

        for line in self.process.stdout:
            self.log(line.strip())

    # =========================
    # 🛑 STOP PROCESS
    # =========================
    def stop(self):
        if self.process:
            self.process.terminate()
            self.log("[STOPPED]")
            self.process = None

    # =========================
    # 📁 SEND FILE
    # =========================
    def send_file(self):
        if self.mode_var.get() != "client":
            messagebox.showinfo("Info", "Switch to Client mode to send files.")
            return

        file_path = filedialog.askopenfilename()

        if not file_path:
            return

        self.log(f"[SENDING FILE] {file_path}")

        # send file via CLI by running a temporary process
        host = self.host_entry.get()
        port = self.port_entry.get()

        # feed file path to stdin
        proc = subprocess.Popen(
            [sys.executable, "cli.py", "--mode", "client", "--host", host, "--port", port],
            stdin=subprocess.PIPE,
            text=True
        )

        proc.stdin.write(file_path + "\nexit\n")
        proc.stdin.flush()
        proc.stdin.close()

# =========================
# 🧭 RUN GUI
# =========================

if __name__ == "__main__":
    root = tk.Tk()
    app = TLSFileGUI(root)
    root.mainloop() 
