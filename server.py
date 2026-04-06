


import os
import atexit
import socket
import threading
import time
import ssl
import json
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa





# alias dictionary to socket
clients = {}     
# public keys for each alias
pub_keys = {}
# lock for thread-safe access to clients and pub_keys
lock = threading.Lock()

# path to keys
CERTIFICATE = os.path.join(os.path.dirname(__file__), "certificate.pem")
KEY  = os.path.join(os.path.dirname(__file__), "private_key.pem")

TESTING_LOG_PATH = None
TESTING_LOG_FILE = None

TESTING_LOG_PATH = os.getenv("SERVER_LOG_PATH")

# for testing
if TESTING_LOG_PATH:
    TESTING_LOG_FILE = open(TESTING_LOG_PATH, "a", encoding="utf-8")
    atexit.register(TESTING_LOG_FILE.close)




# error he


# prints a timestamped log message to terminal
def log(msg):
    line = f"(server {time.strftime('%H:%M:%S')}) {msg}"
    print(line, flush=True)

    # logging to test log file
    if TESTING_LOG_FILE:
        TESTING_LOG_FILE.write(line + "\n")
        TESTING_LOG_FILE.flush()

# runs in a separate thread for each connected client
# tlsSocket = the client's TLS socket, IP_Address = their IP (not used for privacy)
def client_handler(tlsSocket):
    alias = None
    try:
        # keep reading messages from this client until they disconnect
        while True:
            # receive data from the client
            data_from_client = tlsSocket.recv(131072)

            if not data_from_client:
                break

            #  split data by newline
            for line in data_from_client.decode().strip().split("\n"):
                if not line:
                    continue




                
                # parse the JSON message and check what req_type the client wants
                msg = json.loads(line)
                req_type = msg.get("action")

                # client wants to register their alias and public keys
                if req_type == "REGISTER":
                    alias = msg["alias"]
                    pubkey_ed = msg.get("pubkey_ed25519")
                    pubkey_x = msg.get("pubkey_x25519")



                    # reject if  key is missing
                    if not pubkey_ed or not pubkey_x:
                        log(f"rejected ({alias}): missing key")
                        continue


                    # store the alias and keys in lock
                    with lock:
                        pub_keys[alias] = {"ed25519": pubkey_ed, "x25519": pubkey_x}
                        clients[alias] = tlsSocket
                    log(f"registered: ({alias})")
                    tlsSocket.sendall(json.dumps({"status": "ok", "msg": "Connected"}).encode() + b"\n")

                # client wants to look up another user's public keys
                elif req_type == "LOOKUP":
                    target = msg["alias"]
                    with lock:
                        keys = pub_keys.get(target)
                    # return the keys if found, error if not
                    if keys:
                        tlsSocket.sendall(json.dumps({"status": "ok", "pubkey_ed25519": keys["ed25519"], "pubkey_x25519": keys["x25519"]}).encode() + b"\n")
                    else:
                        tlsSocket.sendall(json.dumps({"status": "error", "msg": "Alias not found"}).encode() + b"\n")

                # client wants to send an encrypted message to another alias
                elif req_type == "SEND":
                    to_alias = msg["to"]
                    from_alias = msg.get("from", "anonymous")

                    ciphertext = msg["ciphertext"]


                    # build a new message
                    stripped_msg = json.dumps({
                        "action": "MESSAGE",
                        "from": from_alias,
                        "ciphertext": ciphertext
                    }).encode() + b"\n"

                    #find the recipient's socket connection
                    with lock:
                        to_tlsSocket = clients.get(to_alias)

                    if to_tlsSocket:
                        try:
                            # forward the stripped message to the recipient
                            to_tlsSocket.sendall(stripped_msg)
                            log(f"forwarded: ({from_alias}) to ({to_alias}) (content hidden)")
                            tlsSocket.sendall(json.dumps({"status": "ok", "msg": "Sent"}).encode() + b"\n")
                        except Exception:
                            # recipient is no longer connected, remove them
                            with lock:
                                clients.pop(to_alias, None)
                            tlsSocket.sendall(json.dumps({"status": "error", "msg": "Could not deliver"}).encode() + b"\n")
                    else:
                        tlsSocket.sendall(json.dumps({"status": "error", "msg": "Recipient not online"}).encode() + b"\n")

                # client wants to see all online aliases
                elif req_type == "LIST":
                    with lock:
                        aliases = list(pub_keys.keys())
                    tlsSocket.sendall(json.dumps({"status": "ok", "aliases": aliases}).encode() + b"\n")

    # client disconnected or sent bad data
    except (ConnectionResetError, json.JSONDecodeError):
        pass

    # clean up when client leaves for any reason
    finally:
        if alias:
            with lock:
                clients.pop(alias, None)
                pub_keys.pop(alias, None)
            log(f"disconnected: ({alias})")
        tlsSocket.close()

def generate_tls_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    with open(KEY, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(CERTIFICATE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
 

def main():
    # get host and port from environment variables or default
    HOST = os.getenv("SERVER_HOST", "")

    PORT = int(os.getenv("SERVER_PORT", "8888"))

    if not os.path.exists(CERTIFICATE) or not os.path.exists(KEY):
        generate_tls_cert()

    # set up TLS context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERTIFICATE, KEY)

    # create a TCP socket
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((HOST, PORT))
    tcp_sock.listen(10)

    # wrap the TCP socket with TLS encryption
    tls_server = ctx.wrap_socket(tcp_sock, server_side=True)

    log(f"tls relay server listening on host: {HOST} and port: {PORT}")
    log("only using aliases")

    # accept new connections forever, each one gets its own thread
    while True:
        tlsSocket, IP_Address = tls_server.accept()
        log("new tls connection (IP not logged)")
        threading.Thread(target=client_handler, args=(tlsSocket,), daemon=True).start()

if __name__ == "__main__":
    main()
