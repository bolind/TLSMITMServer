import ssl
import socket
import threading
import argparse

parser = argparse.ArgumentParser(description="Program that acts as a man-in-the-middle TLS server")
parser.add_argument("-l", "--listenport", type=int, default=443, help='Port to listen on, defaults to 443')
parser.add_argument("-p", "--port", type=int, default=443, help="Port to connect to, defaults to 443")
parser.add_argument("--keylogfile", type=str, help="Filename for logging session keys")
parser.add_argument("-H", "--host", type=str, required=True, help="Target host address or IP")
args = parser.parse_args()

MITM_HOST = "0.0.0.0"        # Listen on all interfaces
MITM_PORT = args.listenport  # MITM server port, this is the port this program listens on
TARGET_HOST = args.host      # Server to connect to
TARGET_PORT = args.port      # Port to connect to

# Certificate, generate with: openssl req -x509 -newkey rsa:4096 -keyout mitm.key -out mitm.pem -days 36500 -nodes
MITM_CERT = "mitm.pem"
MITM_KEY = "mitm.key"

def handle_client(client_conn):
    """Handles communication between client and real server."""
    # Establish a secure connection to the real server
    context = ssl.create_default_context()
    if hasattr(context, "keylog_filename") and args.keylogfile:
        context.keylog_filename = args.keylogfile
    context.check_hostname = False  # Disable hostname check
    context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
    with socket.create_connection((TARGET_HOST, TARGET_PORT)) as server_sock:
        with context.wrap_socket(server_sock, server_hostname=TARGET_HOST) as server_conn:
            # Upgrade client connection to TLS
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            client_context.load_cert_chain(certfile=MITM_CERT, keyfile=MITM_KEY)
            with client_context.wrap_socket(client_conn, server_side=True) as tls_client:
                print(f"TLS connection established with {tls_client.getpeername()}")
                while True:
                    data = tls_client.recv(4096)
                    if not data:
                        break  # Connection closed
                    print(f"Client -> Server: {data.decode(errors='ignore')}")
                    server_conn.sendall(data)
                    response = server_conn.recv(4096)
                    if not response:
                        break
                    print(f"Server -> Client: {response.decode(errors='ignore')}")
                    tls_client.sendall(response)


def start_mitm_server():
    """Starts a simple TLS MITM server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((MITM_HOST, MITM_PORT))
    server_socket.listen(5)
    print(f"MITM Proxy running on {MITM_HOST}:{MITM_PORT}")
    while True:
        client_conn, _ = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_conn,)).start()

if __name__ == "__main__":
    start_mitm_server()

