"""
Tests:
1. Basic encrypted send/receive
2. Wrong key cannot decrypt
3. Check server logs for anonymity
4. 20-message stress test with no identity leakage
5. Long message test
6. Same message gives different ciphertexts
7. Sender only learns public keys from LOOKUP
8. Alias independence
"""

import socket
import json
import time
import ssl
import os
import tempfile
import subprocess
import sys
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

HOST = "127.0.0.1"
PORT = 9999
PASSED = 0
FAILED = 0

def result(name, ok, detail=""):
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print(f"  [PASS] {name} {detail}")
    else:
        FAILED += 1
        print(f"  [FAIL] {name} {detail}")

#Generate one signing key pair and one encryption key pair for a client
def gen_keypair():
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    x_priv = x25519.X25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    x_pub = x_priv.public_key()
    ed_pem = ed_pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    x_pem = x_pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return ed_priv, x_priv, ed_pub, x_pub, ed_pem, x_pem

#Encrypt a plaintext message using ephemeral X25519 and AES-GCM
def encrypt(plaintext, pubkey):
    eph_priv = x25519.X25519PrivateKey.generate()
    shared = eph_priv.exchange(pubkey)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"alias-encrypted-messaging"
    ).derive(shared)
    nonce = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode(), None)
    eph_pub = eph_priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    return base64.b64encode(eph_pub + nonce + ct).decode()

#Decrypt a base64 ciphertext using the receiver's private X25519 key
def decrypt(ct_b64, privkey):
    raw = base64.b64decode(ct_b64)
    if len(raw) < 44:
        raise ValueError("Ciphertext too short")
    eph_pub_bytes, nonce, ct = raw[:32], raw[32:44], raw[44:]
    eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared = privkey.exchange(eph_pub)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"alias-encrypted-messaging"
    ).derive(shared)
    return AESGCM(aes_key).decrypt(nonce, ct, None).decode()

#Create a TLS socket for talking to the relay server
def make_tls_sock():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    s.settimeout(5)
    return s

#Ask the OS for a free local port to use during testing
def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

#Send one JSON message over the socket, followed by a newline
def send_json(sock, data):
    sock.sendall(json.dumps(data).encode() + b"\n")

#Receive one JSON message from the socket
def recv_json(sock):
    data = sock.recv(65536)
    return json.loads(data.decode().strip().split("\n")[0])

#Create a client connection and register its alias and public keys
def make_client(alias, pem):
    s = make_tls_sock()
    s.connect((HOST, PORT))
    send_json(s, {"action": "REGISTER", "alias": alias, "pubkey_ed25519": pem["ed25519"], "pubkey_x25519": pem["x25519"]})
    recv_json(s)
    return s

# Start the server in the background
print("Starting server...")
PORT = get_free_port()
log_path = os.path.join(tempfile.gettempdir(), "server_test.log")
server_log_file = open(log_path, "w")
env = os.environ.copy()
env["SERVER_LOG_PATH"] = log_path
env["SERVER_HOST"] = HOST
env["SERVER_PORT"] = str(PORT)
server_proc = subprocess.Popen(
    [sys.executable, "-u", os.path.join(os.path.dirname(__file__), "server.py")],
    stdout=server_log_file, stderr=subprocess.STDOUT, env=env
)
time.sleep(1)

try:
    #TEST 1: Basic encrypted messaging
    print("\n TEST 1: Basic Encrypted Messaging ")
    ed_priv_a, x_priv_a, ed_pub_a, x_pub_a, ed_pem_a, x_pem_a = gen_keypair()
    ed_priv_b, x_priv_b, ed_pub_b, x_pub_b, ed_pem_b, x_pem_b = gen_keypair()

    sock_a = make_client("Client A", {"ed25519": ed_pem_a, "x25519": x_pem_a})
    sock_b = make_client("Client B", {"ed25519": ed_pem_b, "x25519": x_pem_b})

    #Client A looks up Client B's public key
    send_json(sock_a, {"action": "LOOKUP", "alias": "Client B"})
    resp = recv_json(sock_a)
    b_pubkey = serialization.load_pem_public_key(resp["pubkey_x25519"].encode())

    #Client A encrypts and sends a message to Client B
    plaintext = "Hello world!"
    ciphertext = encrypt(plaintext, b_pubkey)
    send_json(sock_a, {"action": "SEND", "from": "Client A", "to": "Client B", "ciphertext": ciphertext})

    time.sleep(0.3)

    _ = recv_json(sock_a)
    msg = recv_json(sock_b)
    decrypted = decrypt(msg["ciphertext"], x_priv_b)

    result("Message delivered", msg["action"] == "MESSAGE")
    result("Plaintext matches", decrypted == plaintext, f"got: '{decrypted}'")
    result("Sender shows alias only", msg["from"] == "Client A" and "127" not in json.dumps(msg))

    #TEST 2: Wrong key test
    print("\n TEST 2: Wrong Key Test")
    ed_priv_c, x_priv_c, ed_pub_c, x_pub_c, ed_pem_c, x_pem_c = gen_keypair()
    sock_c = make_client("Wrong User", {"ed25519": ed_pem_c, "x25519": x_pem_c})

    try:
        decrypt(ciphertext, x_priv_c)
        result("Wrong-key rejected", False)
    except Exception:
        result("Wrong-key rejected", True)

    #TEST 3: Check server logs
    print("\n TEST 3: Server Log Check")
    deadline = time.time() + 3.0
    logs = ""
    while time.time() < deadline:
        time.sleep(0.2)
        server_log_file.flush()
        with open(log_path, "r") as f:
            logs = f.read()
        if "Client A" in logs and "Client B" in logs:
            break
    sanitized = "\n".join([line for line in logs.splitlines() if "listening on" not in line])
    result("No IPs in server logs", "127.0.0.1" not in sanitized and "0.0.0.0" not in sanitized)
    result("Aliases present in logs", "Client A" in logs and "Client B" in logs)
    result("No message in logs", plaintext not in logs)

    #TEST 4: 20-message stress test
    print("\n TEST 4: 20-Message Stress Test")

    sock_a.close()
    sock_b.close()
    sock_c.close()
    time.sleep(0.3)

    ed_priv_a, x_priv_a, ed_pub_a, x_pub_a, ed_pem_a, x_pem_a = gen_keypair()
    ed_priv_b, x_priv_b, ed_pub_b, x_pub_b, ed_pem_b, x_pem_b = gen_keypair()
    sock_a = make_client("Sender", {"ed25519": ed_pem_a, "x25519": x_pem_a})
    sock_b = make_client("Receiver", {"ed25519": ed_pem_b, "x25519": x_pem_b})

    send_json(sock_a, {"action": "LOOKUP", "alias": "Receiver"})
    resp = recv_json(sock_a)
    recv_pubkey = serialization.load_pem_public_key(resp["pubkey_x25519"].encode())

    success_count = 0
    for i in range(20):
        test_msg = f"Test message #{i+1}"
        ct = encrypt(test_msg, recv_pubkey)
        send_json(sock_a, {"action": "SEND", "from": "Sender", "to": "Receiver", "ciphertext": ct})
        time.sleep(0.15)
        _ = recv_json(sock_a)
        incoming = recv_json(sock_b)
        pt = decrypt(incoming["ciphertext"], x_priv_b)
        if pt == test_msg and incoming["from"] == "Sender":
            success_count += 1

    result(f"20-message exchange", success_count == 20, f"({success_count}/20 succeeded)")

    #Check logs one more time
    server_log_file.flush()
    with open(log_path, "r") as f:
        final_logs = f.read()
    final_sanitized = "\n".join([line for line in final_logs.splitlines() if "listening on" not in line])
    real_ip_leaked = "127.0.0.1" in final_sanitized or "0.0.0.0" in final_sanitized
    result("Zero identity leakage in all logs", not real_ip_leaked)

    #TEST 5: Long message test
    print("\n TEST 5: Long Message Test")
    long_msg = "A" * 1000
    ct_long = encrypt(long_msg, recv_pubkey)
    send_json(sock_a, {"action": "SEND", "from": "Sender", "to": "Receiver", "ciphertext": ct_long})
    time.sleep(0.3)
    _ = recv_json(sock_a)
    incoming = recv_json(sock_b)
    pt_long = decrypt(incoming["ciphertext"], x_priv_b)
    result("1000-char message", pt_long == long_msg, f"(length: {len(pt_long)})")

    sock_a.close()
    sock_b.close()

    #TEST 6: Same message, different ciphertext
    print("\n TEST 6: Same Message, Different Ciphertext ")
    ed_priv_a, x_priv_a, ed_pub_a, x_pub_a, ed_pem_a, x_pem_a = gen_keypair()
    ed_priv_b, x_priv_b, ed_pub_b, x_pub_b, ed_pem_b, x_pem_b = gen_keypair()
    sock_a = make_client("UniqueA", {"ed25519": ed_pem_a, "x25519": x_pem_a})
    sock_b = make_client("UniqueB", {"ed25519": ed_pem_b, "x25519": x_pem_b})

    same_msg = "identical message"
    ct1 = encrypt(same_msg, x_pub_b)
    ct2 = encrypt(same_msg, x_pub_b)
    ct3 = encrypt(same_msg, x_pub_b)
    result("Different ciphertexts", ct1 != ct2 != ct3)
    result("All unique ciphertexts decrypt correctly",
           decrypt(ct1, x_priv_b) == decrypt(ct2, x_priv_b) == decrypt(ct3, x_priv_b) == same_msg)

    #TEST 7: Sender only learns public keys
    print("\n TEST 7: Sender Only Learns Public Keys ")
    send_json(sock_a, {"action": "LOOKUP", "alias": "UniqueB"})
    lookup_resp = recv_json(sock_a)
    resp_str = json.dumps(lookup_resp)
    result("LOOKUP returns only public keys",
           "pubkey_ed25519" in lookup_resp and "pubkey_x25519" in lookup_resp)
    result("LOOKUP reveals no IP address", "127" not in resp_str and "0.0.0.0" not in resp_str)
    result("LOOKUP reveals no connection metadata",
           "port" not in resp_str and "time" not in resp_str and "addr" not in resp_str)

    sock_a.close()
    sock_b.close()
    time.sleep(0.3)


    #TEST 8: Alias independence
    print("\n TEST 8: Alias Independence ")
    ed_priv_1, x_priv_1, ed_pub_1, x_pub_1, ed_pem_1, x_pem_1 = gen_keypair()
    ed_priv_2, x_priv_2, ed_pub_2, x_pub_2, ed_pem_2, x_pem_2 = gen_keypair()

    sock_1 = make_client("PersonX", {"ed25519": ed_pem_1, "x25519": x_pem_1})
    sock_2 = make_client("PersonY", {"ed25519": ed_pem_2, "x25519": x_pem_2})

    send_json(sock_1, {"action": "LOOKUP", "alias": "PersonX"})
    resp_x = recv_json(sock_1)
    send_json(sock_1, {"action": "LOOKUP", "alias": "PersonY"})
    resp_y = recv_json(sock_1)

    result("Aliases have independent public keys",
           resp_x["pubkey_x25519"] != resp_y["pubkey_x25519"])

    ct_for_x = encrypt("secret for X", x_pub_1)
    try:
        decrypt(ct_for_x, x_priv_2)
        result("Aliases are independent", False)
    except Exception:
        result("Aliases are independent", True)

    sock_1.close()
    sock_2.close()

    #Final results
    print(f"  Done: {PASSED} passed, {FAILED} failed")

finally:
    server_proc.terminate()
    server_log_file.close()