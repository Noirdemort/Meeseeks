#
# coreutils.py
# EastWinds
#
# Created by Noirdemort.
#

from getpass import getpass
import requests
from Crypto.PublicKey import RSA
from hashlib import sha512
import random
import threading
import socket


class MainFrame:

    def __init__(self, remote_url, public_key, verifier):
        self.RemoteURL = remote_url
        self.ServerPublicKey = public_key
        self.VerificationString = verifier

    def post(self, portal, metadata):
        r = requests.post(self.RemoteURL+portal, metadata)
        return r.text

    def get(self, exfil):
        r = requests.get(self.RemoteURL + exfil)
        return r.text


class CommandLine:

    @staticmethod
    def get_input(field_name, required=True):
        read_data = input("[*] Enter {}: ".format(field_name)).strip()
        while not read_data and required:
            print("[!] Error: {} is required.".format(field_name))
            read_data = input("[*] Enter {}: ".format(field_name)).strip()

        return read_data

    @staticmethod
    def get_secure_input(secure_field):
        read_data = getpass("[*] Enter {}: ".format(secure_field)).strip()
        while not read_data:
            print("[!] Error: {} is required.".format(secure_field))
            read_data = getpass("[*] Enter {}: ".format(secure_field)).strip()

        return read_data


class GhostProtocol:

    @staticmethod
    def encrypt(public_key, message):
        key = RSA.importKey(public_key)
        encrypted_data = key.encrypt(message.encode(), 2048)[0]
        return list(encrypted_data)

    @staticmethod
    def int_array_to_string(arr):
        return ",".join([str(x) for x in arr])

    @staticmethod
    def string_to_int_array(arr):
        arr = arr.split(",")
        return [int(x) for x in arr]

    @staticmethod
    def decrypt(private_key, encrypted_data):
        cipher_text = bytes(encrypted_data)
        key = RSA.importKey(private_key)
        decrypted_data = key.decrypt(cipher_text).decode()
        return decrypted_data

    @staticmethod
    def correlate_pair(public_key, private_key):
        verifier = "fj6nd-37sn5-18ysd-yu65j-y9zjh"
        cipher_text = GhostProtocol.encrypt(public_key, verifier)
        clear_text = GhostProtocol.decrypt(private_key, cipher_text)
        if verifier == clear_text:
            return 1
        return 0

    @staticmethod
    def sha512hash(text):
        return sha512(text.encode()).hexdigest()

    @staticmethod
    def random_integer(m0, m1):
        return random.randint(random.randint(m0, m1)*10, random.randint(m0, m1)*1000)


class ChatSession(threading.Thread):

    def __init__(self, user):
        threading.Thread.__init__(self)
        self.user = user

    def start_server(self):
        """Sets up handling for incoming clients."""
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket.bind(('0.0.0.0', 42042))
        listen_socket.listen(50)

        while True:
            connection, address = listen_socket.accept()
            encrypted_data = connection.recv(4096).decode("utf8")
            clear_text = GhostProtocol.decrypt(self.user.private_key, GhostProtocol.string_to_int_array(encrypted_data))
            username, msg = clear_text.split("BREAK:HERE")
            print("[$] {} : {}".format(username, msg))

        # accept_thread = threading.Thread(target=self.accept_incoming_connections, args=(user,))
        # accept_thread.start()
        # accept_thread.join()
    #
    # def accept_incoming_connections(self, user):
    #     """Sets up handling for incoming clients."""
    #     host = '0.0.0.0'
    #     port = 42042
    #     address = (host, port)
    #
    #     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     server.bind(address)
    #
    #     server.listen(50)
    #     print("[*] Waiting for connection...")
    #     while True:
    #         client, client_address = server.accept()
    #         threading.Thread(target=self.handle_client, args=(user, client, )).start()
    #
    # @staticmethod
    # def handle_client(user, client):
    #     """Handles a single client connection."""
    #     encrypted_data = client.recv(4096).decode("utf8")
    #     clear_text = GhostProtocol.decrypt(user.private_key, GhostProtocol.string_to_int_array(encrypted_data))
    #     username, msg = clear_text.split("BREAK:HERE")
    #     print("[$] {} : {}".format(username, msg))


class User:

    def __init__(self, username, public_key, private_key):
        self.username = username
        self.public_key = public_key
        self.private_key = private_key

    def verify_account(self, central_server):
        print("[*] Starting zero knowledge protocols...")
        encrypted_phrase = central_server.get("proofOfIdentity/"+self.username)
        encrypted_data = GhostProtocol.string_to_int_array(encrypted_phrase)
        print("[*] Decrypting using local keys...")
        id_decrypted = GhostProtocol.decrypt(self.private_key, encrypted_data)
        server_side_proof = GhostProtocol.encrypt(central_server.ServerPublicKey, id_decrypted)
        print("[*] Packaging upload data...")
        upload_data = GhostProtocol.int_array_to_string(server_side_proof)
        print("[*] Establishing Uplink...")
        print("[*] Uploading Data...")
        response = central_server.post("proofOfIdentity/"+self.username, {"key": upload_data})

        if response != "accountVerified":
            print("[!] Error: Poisoned User account!")
            print("[*] Exiting... ")
            exit(1)

        print("[+] Account Verified.")


class ConnectionManager:

    def __init__(self):
        self.connections = {}

    def add_connection(self, central_server, user, required):
        while 1:
            foreign_name = CommandLine.get_input("username for connection")
            encrypted_username = GhostProtocol.int_array_to_string(GhostProtocol.encrypt(central_server.ServerPublicKey, foreign_name))
            requester = GhostProtocol.int_array_to_string(GhostProtocol.encrypt(central_server.ServerPublicKey, user.username))
            res = central_server.post("searchIndex", {"username": encrypted_username, "requester": requester})
            result = GhostProtocol.decrypt(user.private_key, GhostProtocol.string_to_int_array(res))
            if result == "onRecord":
                clientRSAPublicKey = central_server.post("getRSA", {"username": encrypted_username})
                encryptedIpAddr = central_server.post("ipAddr", {"username": encrypted_username, "requester": requester})
                ipAddr = GhostProtocol.decrypt(user.privateKey, GhostProtocol.string_to_int_array(encryptedIpAddr))
                friend = Client(foreign_name, clientRSAPublicKey, ipAddr)
                self.connections[foreign_name] = friend
                action = friend.start_session(user)
                if action == ":switch":
                    self.switch_connection(user)
                elif action == "quit":
                    self.teardown()
            else:
                print("[!] Error:- No such username currently exists. Try again!")

            if not required:
                    break

    def switch_connection(self, user):
        i = 0
        for k in self.connections:
            print("{}. {}".format(i+1, k))
            i += 1

        choice = CommandLine.get_input("one of username no.")
        if int(choice) > i or int(choice) <= 0:
            print("[!] Error: Invalid choice")
            return

        friends_list = list(self.connections.keys())

        self.connections[friends_list[int(choice)-1]].start_session(user)

    def teardown(self):
        for client in self.connections.values():
            client.socket.close()


class Client:

    def __init__(self, username, public_key, ip_address):
        self.username = username
        self.public_key = public_key
        self.ip_address = ip_address

    def start_session(self, user):
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = 42042

        remote_sock.connect((self.ip_address, port))
        self.socket = remote_sock
        while 1:
            msg = CommandLine.get_input("#> ", False)
            if msg == ":connect":
                remote_sock.close()
                stack = "connect"
                break
            elif msg == ":switch":
                remote_sock.close()
                stack = "switch"
                break
            elif msg == "\quit":
                remote_sock.close()
                stack = "quit"
                break
            elif msg == "":
                continue
            else:
                payload = user.username + 'BREAK:HERE' + msg
                encrypted_payload = GhostProtocol.int_array_to_string(GhostProtocol.encrypt(self.public_key, payload))
                remote_sock.send(bytes(encrypted_payload, 'utf-8'))
        return stack

