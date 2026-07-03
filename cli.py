import socket
import struct
import threading
import argparse
import os
import ssl
import sys

SAVE_DIR = "received_files"
os.makedirs(SAVE_DIR, exist_ok=True)

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
            print(f"\r[sent] {sent}/{file_size} bytes", end="", flush=True)
    print(f"\n[sent] {filename} done")

def handle_incoming(conn):
    try:
        while True:
            msg_type = recv_exact(conn, 1)
            if msg_type == b"\x01":
                name_len = struct.unpack("!I", recv_exact(conn, 4))[0]
                file_size = struct.unpack("!Q", recv_exact(conn, 8))[0]
                filename = recv_exact(conn, name_len).decode(errors="ignore")

                # Basic path traversal guard
                filename = os.path.basename(filename)
                path = os.path.join(SAVE_DIR, filename)

                print(f"\n[recv] {filename} ({file_size} bytes)")
                received = 0
                try:
                    with open(path, "wb") as f:
                        while received < file_size:
                            chunk = conn.recv(min(4096, file_size - received))
                            if not chunk:
                                raise ConnectionError("Lost connection")
                            f.write(chunk)
                            received += len(chunk)
                            print(f"\r[recv] {received}/{file_size} bytes", end="", flush=True)
                    print(f"\n[saved] {path}")
                except Exception:
                    if os.path.exists(path):
                        os.remove(path) # delete partial file
                    raise
    except Exception as e:
        print("[error]", e)

def interactive_sender(conn):
    print("Type file paths to send. Type 'exit' to quit.")
    while True:
        try:
            path = input("> ").strip()
            if path.lower() == "exit":
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                break
            if os.path.isfile(path):
                send_file(conn, path)
            else:
                print("Not a file")
        except (EOFError, KeyboardInterrupt):
            conn.close()
            break

def create_server_context(certfile, keyfile):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2 # no old TLS
    return ctx

def create_client_context():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = False # set True + use valid cert for prod
    ctx.verify_mode = ssl.CERT_NONE # use CERT_REQUIRED + ca cert for prod
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx

def run_server(host, port, cert, key):
    ctx = create_server_context(cert, key)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(1)
        print(f"[listening] {host}:{port} TLS")
        conn, addr = sock.accept()
        with ctx.wrap_socket(conn, server_side=True) as tls_conn:
            print(f"[connected] {addr} TLSv{tls_conn.version()}")
            threading.Thread(target=handle_incoming, args=(tls_conn,), daemon=True).start()
            interactive_sender(tls_conn)

def run_client(host, port):
    ctx = create_client_context()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_conn:
            tls_conn.connect((host, port))
            print(f"[connected] {host}:{port} TLSv{tls_conn.version()}")
            threading.Thread(target=handle_incoming, args=(tls_conn,), daemon=True).start()
            interactive_sender(tls_conn)

def main():
    parser = argparse.ArgumentParser(description="TLS file sender")
    parser.add_argument("--mode", choices=["server", "client"], required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--cert", default="cert.pem", help="server cert")
    parser.add_argument("--key", default="key.pem", help="server key")
    args = parser.parse_args()

    if args.mode == "server":
        if not os.path.exists(args.cert) or not os.path.exists(args.key):
            sys.exit("Missing cert.pem/key.pem. Generate with openssl first.")
        run_server(args.host, args.port, args.cert, args.key)
    else:
        run_client(args.host, args.port)

if __name__ == "__main__":
    main()


"""
Usage:
Make cert:
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost" 

# Terminal 1: Server
python tlssender.py --mode server --cert cert.pem --key key.pem --port 5001

# Terminal 2: Client
python tlssender.py --mode client --host 127.0.0.1 --port 5001
> test.zip
"""
