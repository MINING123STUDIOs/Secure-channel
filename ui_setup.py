import sys
import subprocess
import threading

try:
    import customtkinter as ctk
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "customtkinter"])
    import customtkinter as ctk


REQUIRED = [
    "customtkinter"
]


def install_package(pkg, log_fn):
    log_fn(f"Installing {pkg}...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
    log_fn(f"✔ {pkg} installed")


class SetupWizard(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("TLS File Sender Setup Wizard")
        self.geometry("600x400")

        self.label = ctk.CTkLabel(self, text="🧙 Setup Wizard", font=("Arial", 24))
        self.label.pack(pady=20)

        self.log_box = ctk.CTkTextbox(self, width=500, height=200)
        self.log_box.pack(pady=10)

        self.btn = ctk.CTkButton(self, text="Start Setup", command=self.start_setup)
        self.btn.pack(pady=10)

        self.status = ctk.CTkLabel(self, text="")
        self.status.pack()

    def log(self, msg):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    def start_setup(self):
        self.btn.configure(state="disabled")
        threading.Thread(target=self.run_setup, daemon=True).start()

    def run_setup(self):
        self.log("🧙 Checking environment...")

        for pkg in REQUIRED:
            try:
                __import__(pkg)
                self.log(f"✔ {pkg} already installed")
            except ImportError:
                self.log(f"❌ Missing {pkg}")
                install_package(pkg, self.log)

        self.log("\n✨ Setup complete!")
        self.status.configure(text="Ready to run CLI + UI ✨")


if __name__ == "__main__":
    app = SetupWizard()
    app.mainloop()
