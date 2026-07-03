import socket
import struct
import threading
import argparse
import os
import sys

SAVE_DIR = "received_files"
os.makedirs(SAVE_DIR, exist_ok=True)


# -------------------------
# Low-level helpers
# -------------------------

def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def send_file(conn, filepath):
    filename = os.path.basename(filepath)
    file_size = os.path.getsize(filepath)

    conn.sendall(b"\x01")
    conn.sendall(struct.pack("!I", len(filename)))
    conn.sendall(struct.pack("!Q", file_size))
    conn.sendall(filename.encode())

    sent = 0
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            conn.sendall(chunk)
            sent += len(chunk)

    print(f"[sent] {filename} ({sent} bytes)")


def handle_incoming(conn):
    while True:
        try:
            msg_type = recv_exact(conn, 1)
            if not msg_type:
                break

            if msg_type == b"\x01":
                name_len = struct.unpack("!I", recv_exact(conn, 4))[0]
                file_size = struct.unpack("!Q", recv_exact(conn, 8))[0]
                filename = recv_exact(conn, name_len).decode()

                path = os.path.join(SAVE_DIR, filename)

                print(f"\n[recv] {filename} ({file_size} bytes)")

                received = 0
                with open(path, "wb") as f:
                    while received < file_size:
                        chunk = conn.recv(min(4096, file_size - received))
                        if not chunk:
                            raise ConnectionError("Lost connection")
                        f.write(chunk)
                        received += len(chunk)

                print(f"[saved] {path}")

        except Exception as e:
            print("[error]", e)
            break


# -------------------------
# CLI / connection setup
# -------------------------

def interactive_sender(conn):
    print("Type file paths to send. Type 'exit' to quit.")
    while True:
        path = input("> ").strip()
        if path.lower() == "exit":
            conn.close()
            break
        if os.path.isfile(path):
            send_file(conn, path)
        else:
            print("Not a file")


def run_server(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)

    print(f"[listening] {host}:{port}")
    conn, addr = s.accept()
    print(f"[connected] {addr}")

    threading.Thread(target=handle_incoming, args=(conn,), daemon=True).start()
    interactive_sender(conn)


def run_client(host, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((host, port))

    print(f"[connected] {host}:{port}")

    threading.Thread(target=handle_incoming, args=(conn,), daemon=True).start()
    interactive_sender(conn)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["server", "client"], required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()

    if args.mode == "server":
        run_server(args.host, args.port)
    else:
        run_client(args.host, args.port)


if __name__ == "__main__":
    main()
