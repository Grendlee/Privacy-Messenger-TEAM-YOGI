import socket
import threading

import json
import sys

import os
from pathlib import Path

import ssl
import queue
import json


try:
    import socks
except ImportError:
    print("Error: PySocks is required. Install it with: pip install pysocks")
    sys.exit(1)

# signing and key exchange
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519


#  key encoding/decoding
from cryptography.hazmat.primitives import serialization, hashes


#    key derivation to create AES keys from shared secrets
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# AES-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



import base64


class Client:

    
    def __init__(self, alias, onion_host, onion_port=8888, socks_host="127.0.0.1", socks_port=9050):


        

        # directory to store private keys
        self.directory_private_keys = os.path.join(os.path.dirname(__file__), ".private_keys")

        os.makedirs(self.directory_private_keys, exist_ok=True)

        self.alias = alias

        # onion service address and socks proxy address
        self.onion_host = onion_host
        self.encrypted_tor_sockets_host = socks_host

        #onion service port and socks proxy port
        self.onion_port = onion_port
        self.encrypted_tor_sockets_port = socks_port

        self.create_or_load_private_keys()

        # save public keys as PEM strings for serv registration
        self.public_key_ed25519_PEM_string = self.public_key_ed25519.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        
        self.public_key_x25519_PEM_string = self.public_key_x25519.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        #set up TLS context
        self.TLS_context = ssl.create_default_context()
        self.TLS_context.check_hostname = False
        self.TLS_context.verify_mode = ssl.CERT_NONE

        # cache of other users so no need to refetch after each msg
        self.key_cache = {}

        # thread-safe queue routing server responses to caller
        # receive_server_json connect
        self.server_response_queue = queue.Queue()

    def create_or_load_private_keys(self):
        ed25519_key_path = Path(self.directory_private_keys) / f"{self.alias}_ed25519.pem"
        x25519_key_path = Path(self.directory_private_keys) / f"{self.alias}_x25519.pem"

        # if keys already exist
        if ed25519_key_path.exists() and x25519_key_path.exists():
            self.private_key_ed25519 = serialization.load_pem_private_key(ed25519_key_path.read_bytes(), password=None)
            self.private_key_x25519 = serialization.load_pem_private_key(x25519_key_path.read_bytes(), password=None)
        else:
            self.private_key_ed25519 = ed25519.Ed25519PrivateKey.generate()
            self.private_key_x25519 = x25519.X25519PrivateKey.generate()


            ed25519_key_path.write_bytes(self.private_key_ed25519.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            
            x25519_key_path.write_bytes(self.private_key_x25519.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            

        self.public_key_ed25519 = self.private_key_ed25519.public_key()
        self.public_key_x25519 = self.private_key_x25519.public_key()

    def get_users_public_key(self, target_alias):
        
        
        if target_alias in self.key_cache:
            return self.key_cache[target_alias]
        else:
        
            # ask server for the user's public keys instead
            self.send_to_server_json({"action": "LOOKUP", "alias": target_alias})
            response = self.receive_server_json()
            
            if response.get("status") != "ok":
                print(f"[ERROR] {response.get('msg')}")
                return None

            # decode and cache 
            ed_key = serialization.load_pem_public_key(response["pubkey_ed25519"].encode())
            x_key = serialization.load_pem_public_key(response["pubkey_x25519"].encode())

            self.key_cache[target_alias] = {"ed25519": ed_key, "x25519": x_key}

            return self.key_cache[target_alias]
        
    def receive_server_json(self):
        # print(f"waiting server resp")
        return self.server_response_queue.get()
    

    def send_to_server_json(self, data):
        self.encrypted_tor_socket.sendall(json.dumps(data).encode() + b"\n")

    

    # connect to the server through tor
    def connect_to_onion_server(self):


        tor_socket_not_encrypted = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)

        tor_socket_not_encrypted.set_proxy(socks.SOCKS5, self.encrypted_tor_sockets_host, self.encrypted_tor_sockets_port, True)


        # connect server
        tor_socket_not_encrypted.connect((self.onion_host, self.onion_port))
        
        # wrap TLS encryption
        self.encrypted_tor_socket = self.TLS_context.wrap_socket(tor_socket_not_encrypted, server_hostname="localhost")
        
        #thread listen for incoming messages
        threading.Thread(target=self.listen_loop, daemon=True).start()
        
        # register this client with the server
        self.send_to_server_json({
            "action": "REGISTER",
            "alias": self.alias,
            "pubkey_ed25519": self.public_key_ed25519_PEM_string,
            "pubkey_x25519": self.public_key_x25519_PEM_string
        })
        response = self.server_response_queue.get()
        print(f"({self.alias}) {response.get('msg', 'Connected!')}")
    

    def encrypt_message(self, plaintext, recipient_pubkey):
        # ECIES


        throwaway_private_key = x25519.X25519PrivateKey.generate()

        #key exchange
        shared_secret = throwaway_private_key.exchange(recipient_pubkey)


        # derive an AES key 
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"alias-encrypted-messaging").derive(shared_secret)

        nonce = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode(), None)
        
        throwaway_public_key = throwaway_private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        payload = throwaway_public_key + nonce + ciphertext
        
        return base64.b64encode(payload).decode()

    # decrypt a received message
    def decrypt_message(self, ciphertext_b64):
        decoded_payload = base64.b64decode(ciphertext_b64)


        throwaway_public_key_bytes, nonce, ciphertext = decoded_payload[:32], decoded_payload[32:44], decoded_payload[44:]

        throwaway_public_key = x25519.X25519PublicKey.from_public_bytes(throwaway_public_key_bytes)


        shared_secret = self.private_key_x25519.exchange(throwaway_public_key)

        aes_key = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=None, info=b"alias-encrypted-messaging"
        ).derive(shared_secret)

        # log ere
        return AESGCM(aes_key).decrypt(nonce, ciphertext, None).decode()
    
    

    def send_message(self, target_alias, plaintext):

        keys = self.get_users_public_key(target_alias)
        
        if not keys:
            return False
        else:
            # encrypt the message
            ciphertext = self.encrypt_message(plaintext, keys["x25519"])

            # sign the ciphertext with  Ed25519 identity key
            signature = self.private_key_ed25519.sign(ciphertext.encode())
            signature_base64 = base64.b64encode(signature).decode()

            #send to server
            self.send_to_server_json({
                "action": "SEND",
                "from": self.alias,
                "to": target_alias,
                "ciphertext": ciphertext,
                "signature": signature_base64
            })

            response = self.receive_server_json()

            print(f"({self.alias}) {response.get('msg', 'Sent')}")

            return response.get("status") == "ok"

    def listen_loop(self):

        
        while True:
            try:
                received_data = self.encrypted_tor_socket.recv(65536) # no size limit so far
                
                if not received_data:
                    break

                for line in received_data.decode().strip().split("\n"):
                    if not line:
                        continue
                    message = json.loads(line)

                    if message.get("action") != "MESSAGE":

                        self.server_response_queue.put(message)

                        continue
                    sender_alias = message["from"]

                    try:
                        # verify the sender's signature with Ed25519 public key
                        sender_keys = self.key_cache.get(sender_alias)
                        if sender_keys and message.get("signature"):
                            sig = base64.b64decode(message["signature"])
                            sender_keys["ed25519"].verify(sig, message["ciphertext"].encode())

                        decrypted_message = self.decrypt_message(message["ciphertext"])

                        print(f"\n({sender_alias}): {decrypted_message}")
                    except Exception:
                        print(f"\n({sender_alias}): #decryption or verification failed#")
                    print(f"({self.alias}): ", end="", flush=True)
            except Exception:
                break

    def list_users(self):
        self.send_to_server_json({"action": "LIST"})

        response = self.receive_server_json()
        # list all conecte aliases
        print(f"Online aliases: {', '.join(response.get('aliases', []))}")

    def run(self):
        self.connect_to_onion_server()

        print(f"\nCommands:  /send <alias> <message>  |  /show_online  |  /leave\n")
        
        while True:
            try:
                line = input(f"({self.alias}): ").strip()
                if not line:
                    continue
                if line == "/leave":
                    self.encrypted_tor_socket.close()
                    break

                elif line == "/show_online":
                    self.list_users()

                elif line.startswith("/send "):
                    
                    parts = line.split(" ", 2)
                    if len(parts) < 3:
                        print("Format: /send <alias> <message>")
                        continue
                    else:
                        self.send_message(parts[1], parts[2])
                else:
                    # eror fix
                    print("Wrong. Use /send, /show_online, or /leave")
            except (EOFError, KeyboardInterrupt):
                break
        self.encrypted_tor_socket.close()


if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("Format: python client.py <alias> <onion_host>")
        sys.exit(1)
        
    alias = sys.argv[1]

    host = sys.argv[2]

    if len(sys.argv) > 3:
        port = int(sys.argv[3])
    else:
        port = 8888



    socks_host = os.getenv("SOCKS_HOST", "127.0.0.1")
    # default for TOR
    socks_port = int(os.getenv("SOCKS_PORT", "9050"))

    Client(alias, host, port, socks_host=socks_host, socks_port=socks_port).run()
