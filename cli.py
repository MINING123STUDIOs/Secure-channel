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

# =========================
# 🌸 CONFIG
# =========================

SAVE_DIR = "received_files"
os.makedirs(SAVE_DIR, exist_ok=True)

LOG_FILE = "tlssender.log"

MAGIC = b"TLSF"
VERSION = 1

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
# 🔐 TLS
# =========================

def create_server_context(certfile, keyfile):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def create_client_context(cafile=None, insecure=False):
    if insecure:
        return ssl._create_unverified_context()

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    if cafile:
        ctx.load_verify_locations(cafile=cafile)

    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    return ctx

# =========================
# 📦 FILE UTILS
# =========================

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.digest()


def safe_filename(name):
    name = os.path.basename(name)
    base, ext = os.path.splitext(name)

    candidate = name
    i = 1

    while os.path.exists(os.path.join(SAVE_DIR, candidate)):
        candidate = f"{base}({i}){ext}"
        i += 1

    return candidate

# =========================
# 📡 KEEPALIVE
# =========================

def send_keepalive(conn):
    try:
        conn.sendall(bytes([MSG_KEEPALIVE]))
    except Exception:
        pass

# =========================
# 📤 SEND FILE
# =========================

def send_file(conn, filepath):
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    filehash = sha256_file(filepath)

    log(f"[SEND] {filename} ({filesize} bytes)")

    header = (
        bytes([MSG_FILE_BEGIN]) +
        struct.pack("!I", len(filename)) +
        struct.pack("!Q", filesize) +
        filehash +
        filename.encode()
    )

    send_all(conn, header)

    sent = 0
    start = time.time()

    with open(filepath, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            send_all(conn, chunk)
            sent += len(chunk)

            speed = sent / max(time.time() - start, 0.0001)

            print(
                f"\r{sent}/{filesize} bytes | "
                f"{speed/1024/1024:.2f} MB/s",
                end=""
            )

    print("\n[SEND COMPLETE]")

# =========================
# 📥 RECEIVE FILES
# =========================

def handle_incoming(conn):
    try:
        while True:
            msg_type = recv_exact(conn, 1)[0]

            if msg_type == MSG_KEEPALIVE:
                continue

            if msg_type == MSG_GOODBYE:
                log("[REMOTE CLOSED CONNECTION]")
                break

            if msg_type == MSG_FILE_BEGIN:
                name_len = struct.unpack("!I", recv_exact(conn, 4))[0]
                file_size = struct.unpack("!Q", recv_exact(conn, 8))[0]
                file_hash = recv_exact(conn, 32)
                filename = recv_exact(conn, name_len).decode(errors="ignore")

                filename = safe_filename(filename)
                path = os.path.join(SAVE_DIR, filename)

                log(f"[RECV] {filename} ({file_size} bytes)")

                received = 0
                h = hashlib.sha256()

                try:
                    with open(path, "wb") as f:
                        while received < file_size:
                            chunk = conn.recv(min(CHUNK_SIZE, file_size - received))
                            if not chunk:
                                raise ConnectionError("Lost connection")

                            f.write(chunk)
                            h.update(chunk)
                            received += len(chunk)

                            print(f"\r{received}/{file_size} bytes", end="")

                    print("\n[RECEIVED COMPLETE]")

                    if h.digest() != file_hash:
                        log_error("[HASH MISMATCH]")
                        os.remove(path)
                        continue

                    log(f"[OK] Saved {path}")

                except Exception as e:
                    log_error(f"[ERROR] {e}")
                    if os.path.exists(path):
                        os.remove(path)

    except Exception as e:
        log_error(f"[CONNECTION ERROR] {e}")

# =========================
# 💬 SENDER LOOP
# =========================

def interactive_sender(conn):
    log("Type file paths or 'exit'")

    while True:
        path = input("> ").strip()

        if path.lower() == "exit":
            try:
                conn.sendall(bytes([MSG_GOODBYE]))
            except:
                pass
            conn.close()
            break

        if os.path.isfile(path):
            send_file(conn, path)
        else:
            log_error("Invalid file")

# =========================
# 🌐 SERVER
# =========================

def client_thread(conn, addr):
    log(f"[CONNECTED] {addr}")
    try:
        handle_incoming(conn)
    finally:
        conn.close()
        log(f"[DISCONNECTED] {addr}")


def run_server(host, port, cert, key):
    ctx = create_server_context(cert, key)

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen()

    log(f"[SERVER] {host}:{port}")

    while True:
        conn, addr = sock.accept()
        tls = ctx.wrap_socket(conn, server_side=True)

        threading.Thread(
            target=client_thread,
            args=(tls, addr),
            daemon=True
        ).start()

# =========================
# 💻 CLIENT
# =========================

def run_client(host, port, insecure=False, cafile=None):
    ctx = create_client_context(cafile, insecure)

    sock = socket.socket()
    sock.connect((host, port))   # FIXED ORDER

    conn = ctx.wrap_socket(sock, server_hostname=host)

    log("[CLIENT CONNECTED]")

    threading.Thread(
        target=handle_incoming,
        args=(conn,),
        daemon=True
    ).start()

    interactive_sender(conn)

# =========================
# 🧭 MAIN
# =========================

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["server", "client"], required=True)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5001)
    p.add_argument("--cert", default="cert.pem")
    p.add_argument("--key", default="key.pem")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--cafile", default=None)

    args = p.parse_args()

    if args.mode == "server":
        run_server(args.host, args.port, args.cert, args.key)
    else:
        run_client(args.host, args.port, args.insecure, args.cafile)

if __name__ == "__main__":
    main()
