import socket
import struct
import threading
import argparse
import os
import ssl
import sys
import hashlib
import time
import logging
from datetime import datetime

# =========================
# 🌸 CONFIG + CONSTANTS
# =========================

SAVE_DIR = "received_files"
os.makedirs(SAVE_DIR, exist_ok=True)

LOG_FILE = "tlssender.log"

MAGIC = b"TLSF"   # protocol identifier
VERSION = 1

# Message types
MSG_FILE_BEGIN = 0x01
MSG_KEEPALIVE  = 0x02
MSG_ERROR      = 0x03
MSG_GOODBYE    = 0x04

CHUNK_SIZE = 4096

# =========================
# 📝 LOGGING
# =========================

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

def log(msg):
    print(msg)
    logging.info(msg)

def log_error(msg):
    print(msg)
    logging.error(msg)

# =========================
# 🔧 PROTOCOL HELPERS
# =========================

def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        data += chunk
    return data


def send_all(conn, data):
    conn.sendall(data)


# =========================
# 🔐 TLS CONTEXTS
# =========================

def create_server_context(certfile, keyfile):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def create_client_context(cafile=None, insecure=False):
    """
    insecure=True is ONLY for local testing.
    """
    if insecure:
        ctx = ssl._create_unverified_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # If no CA provided, system trust store is used
    if cafile:
        ctx.load_verify_locations(cafile=cafile)

    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    return ctx


# =========================
# 📦 FILE UTILITIES
# =========================

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


def safe_filename(name):
    name = os.path.basename(name)
    base, ext = os.path.splitext(name)

    candidate = name
    counter = 1

    while os.path.exists(os.path.join(SAVE_DIR, candidate)):
        candidate = f"{base}({counter}){ext}"
        counter += 1

    return candidate


# =========================
# 📊 PROGRESS DISPLAY
# =========================

def format_speed(bytes_sent, start_time):
    elapsed = max(time.time() - start_time, 0.0001)
    return bytes_sent / elapsed


def format_eta(total, sent, speed):
    if speed <= 0:
        return "?"
    remaining = total - sent
    return remaining / speed

# =========================
# 📡 KEEPALIVE
# =========================

def send_keepalive(conn):
    try:
        conn.sendall(bytes([MSG_KEEPALIVE]))
    except Exception:
        pass


# =========================
# 📤 SENDING FILES
# =========================

def send_file(conn, filepath):
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    filehash = sha256_file(filepath)

    start_time = time.time()
    sent = 0

    log(f"[SEND] {filename} ({filesize} bytes)")

    # FILE_BEGIN packet
    header = (
        bytes([MSG_FILE_BEGIN]) +
        struct.pack("!I", len(filename)) +
        struct.pack("!Q", filesize) +
        filehash +
        filename.encode()
    )

    send_all(conn, header)

    # stream file
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            send_all(conn, chunk)
            sent += len(chunk)

            speed = format_speed(sent, start_time)
            eta = format_eta(filesize, sent, speed)

            print(
                f"\r{sent}/{filesize} bytes "
                f"| {speed/1024/1024:.2f} MB/s "
                f"| ETA {eta:.1f}s",
                end="",
                flush=True
            )

    print("\n[SEND COMPLETE]")
    logging.info(f"Sent {filename} successfully")


# =========================
# 📥 RECEIVING FILES
# =========================

def handle_incoming(conn):
    """
    Handles incoming stream (runs in background thread)
    """

    try:
        while True:
            msg_type = recv_exact(conn, 1)[0]

            # -------------------------
            # KEEPALIVE
            # -------------------------
            if msg_type == MSG_KEEPALIVE:
                continue

            # -------------------------
            # FILE TRANSFER
            # -------------------------
            if msg_type == MSG_FILE_BEGIN:
                name_len = struct.unpack("!I", recv_exact(conn, 4))[0]
                file_size = struct.unpack("!Q", recv_exact(conn, 8))[0]
                file_hash = recv_exact(conn, 32)
                filename = recv_exact(conn, name_len).decode(errors="ignore")

                filename = safe_filename(filename)
                path = os.path.join(SAVE_DIR, filename)

                log(f"[RECV] {filename} ({file_size} bytes)")

                received = 0
                start_time = time.time()

                h = hashlib.sha256()

                try:
                    with open(path, "wb") as f:
                        while received < file_size:
                            chunk = conn.recv(min(CHUNK_SIZE, file_size - received))
                            if not chunk:
                                raise ConnectionError("Connection lost during transfer")

                            f.write(chunk)
                            h.update(chunk)

                            received += len(chunk)

                            speed = format_speed(received, start_time)
                            eta = format_eta(file_size, received, speed)

                            print(
                                f"\r{received}/{file_size} bytes "
                                f"| {speed/1024/1024:.2f} MB/s "
                                f"| ETA {eta:.1f}s",
                                end="",
                                flush=True
                            )

                    print("\n[WRITE COMPLETE] Verifying hash...")

                    if h.digest() != file_hash:
                        log_error("[ERROR] Hash mismatch! File corrupted.")
                        os.remove(path)
                        continue

                    log(f"[OK] Saved {path}")

                except Exception as e:
                    log_error(f"[RECV ERROR] {e}")

                    if os.path.exists(path):
                        os.remove(path)

    except Exception as e:
        log_error(f"[CONNECTION ERROR] {e}")


# =========================
# 💬 INTERACTIVE SENDER
# =========================

def interactive_sender(conn):
    log("Type file paths to send. Type 'exit' to quit.")

    while True:
        try:
            path = input("> ").strip()

            if path.lower() == "exit":
                try:
                    conn.sendall(bytes([MSG_GOODBYE]))
                except Exception:
                    pass

                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass

                conn.close()
                break

            if os.path.isfile(path):
                send_file(conn, path)
            else:
                log_error("Not a valid file path")

        except (EOFError, KeyboardInterrupt):
            try:
                conn.close()
            except Exception:
                pass
            break

# =========================
# 🌐 SERVER (MULTI-CLIENT)
# =========================

def client_thread(conn, addr):
    log(f"[CONNECTED] {addr}")
    try:
        handle_incoming(conn)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        log(f"[DISCONNECTED] {addr}")


def run_server(host, port, cert, key):
    ctx = create_server_context(cert, key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen()

        log(f"[SERVER] Listening on {host}:{port}")

        while True:
            conn, addr = sock.accept()

            try:
                tls_conn = ctx.wrap_socket(conn, server_side=True)
            except Exception as e:
                log_error(f"[TLS ERROR] {e}")
                conn.close()
                continue

            threading.Thread(
                target=client_thread,
                args=(tls_conn, addr),
                daemon=True
            ).start()


# =========================
# 💻 CLIENT
# =========================

def run_client(host, port, insecure=False, cafile=None):
    ctx = create_client_context(cafile=cafile, insecure=insecure)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        tls_conn = ctx.wrap_socket(sock, server_hostname=host)

        tls_conn.connect((host, port))
        log(f"[CLIENT] Connected to {host}:{port}")

        threading.Thread(
            target=handle_incoming,
            args=(tls_conn,),
            daemon=True
        ).start()

        interactive_sender(tls_conn)


# =========================
# 🧭 MAIN CLI
# =========================

def main():
    parser = argparse.ArgumentParser(description="TLS File Sender (Upgraded)")

    parser.add_argument("--mode", choices=["server", "client"], required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)

    parser.add_argument("--cert", default="cert.pem")
    parser.add_argument("--key", default="key.pem")

    parser.add_argument("--cafile", default=None)
    parser.add_argument("--insecure", action="store_true")

    args = parser.parse_args()

    if args.mode == "server":
        if not os.path.exists(args.cert) or not os.path.exists(args.key):
            sys.exit("Missing cert/key. Generate with OpenSSL first.")

        run_server(args.host, args.port, args.cert, args.key)

    else:
        run_client(
            args.host,
            args.port,
            insecure=args.insecure,
            cafile=args.cafile
        )


if __name__ == "__main__":
    main()
