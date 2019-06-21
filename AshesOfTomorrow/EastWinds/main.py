from coreutils import *
from interface import *
from pathlib import Path

# declaration and initialization

server_key = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv3Oax38lSgq+w1VxmWdn
tZS0bQo2vGQAQLH+fnm2MIBmwISK3menm5zyPfOM56KxtikWOUeGqDd6kIJ+jtVv
tNxGP78o0NC/Fm72Noi52FlD4ksNsoqEQcW1LYqEgtGq8nJC5sW/UyY0IE+pE6kp
5WG9d3CH5EFq/BJtVhr4oOyP2vACoIp4oKByX74xHZ1V4lLejrECaQDLTbK8rivw
N4D/ryqk/yVoF6daTmjPFnpUEfnltoc+cg8kVhWZiOL5BQG3u/KPQ6jTIE73mTNs
X7YiRHs1IzfRFB6a/rP/xbzpDdRfyFxj0Or6roLIiCRAn8l9CZzC1xaKv4ajQPbj
1cuV2SgoAccD2TgTCX1rNXe/A1oGhISnFz98thwIyosOZRb3AS+L/ik2X/RHePL/
hZ9XsnG5+WIQCSL/olcmHUNRCuUhttIjQUPiD7D5N0uODV5OYo6zzmlF/SoLz9O+
F2xxwAtpLqYc3EJDHmzo74KI03qkrlyiD14Q609rUdi1qaFIAIjzeGEJSOjRDfbc
2tCfS3Il7fWmlk+oNzxl6I7QBV0AXFITnebXE0+MiNoIYzAljAFZDa6YW+nSZrzM
3Vrqdzg31tsVuPYNyYPzzpmilelUhcb9ssLPX+pYbXvLWHyAEJ1xKxLTarmY2Tnq
DZ3A/rK1a6GDuErIlQShVj8CAwEAAQ==
-----END PUBLIC KEY-----"""
central_server = MainFrame(remote_url="https://stygian.herokuapp.com/", public_key=server_key, verifier="AI8RM-D3JKD-57UEW-EUYDE-0H684-3HXHW-WEF14-6DFS2-SJ97BS")
cmdInterface = CommandLine()
ghost = GhostProtocol()

#  #######################******** START PHASE 0 ********##############################

# verify local public key with server

print("[*] Verifying local data...")

signature = ghost.encrypt(central_server.ServerPublicKey, central_server.VerificationString)
print("[*] Initializing encryption protocols... ")

exportSignature = ghost.int_array_to_string(signature)

print("[*] Uploading Signature...")
verification = central_server.post("verify", {"signature": exportSignature})

if verification != "verified":
    print("[!] Verification failed!")
    print("[!] Invalid Public Key. Try updating.")
    exit(1)


print("[+] Signature Verified.")

#  #######################******** END PHASE 0 ********##############################


# TODO: - registration phase - p2p based registartion

#  #######################******** START PHASE 1 ********##############################


initAction = account_interface()

if initAction == 0:
    print("[*] Unaccountable behaviour detected!")
    print("[!] Exiting...")
    exit(1)


username = cmdInterface.get_input("username")
home = str(Path.home())
with open("{}/winds/{}.pub".format(home, username)) as file:
    public_key = file.read()

with open("{}/winds/{}".format(home, username)) as file:
    private_key = file.read()

if not private_key or not public_key:
    print("[!] Error: Couldn't find public and private key pair")
    print("[*] Exiting...")
    exit(1)

user = User(username, public_key, private_key)
encrypted_username = ghost.int_array_to_string(ghost.encrypt(central_server.ServerPublicKey, user.username))

print("[*] Preparing encryption cache... ")


if initAction == 1:
    user.verify_account(central_server)
elif initAction == 2:
    # registration
    # check uniqueness
    print("[*] Verifying public key... ")

    unique = central_server.post("unique", {"user": encrypted_username})

    if unique != "unique":
        print("[!] Error - Public Key already exists.")
        print("[*] Exiting...")
        exit(1)

    pairCompatible = ghost.correlate_pair(user.public_key, user.private_key)
    if not pairCompatible:
        print("[!] Error: Breached RSA Pairs.")
        print("[*] Exiting...")
        exit(1)

    print("[*] Establishing uplink and storing username and public key")
    upload_user_signature = ghost.int_array_to_string(ghost.encrypt(central_server.ServerPublicKey, user.username))

    upload_verification = central_server.post("store",  {"user": upload_user_signature, "rsa": user.public_key})
    if upload_verification != "secured":
        print("[!] Error: Identification Signature storage failure.")
        print("Exiting...")
        exit(1)

    print("[+] Account successfully created!")

elif initAction == 3:
    user.verify_account(central_server)
    accountStatus = central_server.post( "delete", {"user": encrypted_username})
    if accountStatus == "deleted":
        print("[-] Account Deleted.")
        print("[*] Exiting...")
        exit(0)

    print("[!] Account Deletion Unsuccessful! Try again.")
    exit(1)

else:
    print("[!] Unrecognizable behaviour detected.")
    print("[*] Exiting...")
    exit(1)


print("[+] Identity shield activated.")


# END:- server knows about my online status

# #######################******** END PHASE 1 ********##############################


# #######################******** START PHASE 2 ********##############################

# Start local server at 42042

chat = ChatSession(user)
chat.start()
#    #######################******** END PHASE 2 ********##############################

#    #######################******** START PHASE 3 ********##############################

# Query User & Initiate session with selected host

chat_manager = ConnectionManager()
chat_manager.add_connection(central_server, user, True)

#   #######################******** END PHASE 3 ********##############################


# #######################******** START PHASE 4 ********##############################

# tear down the whole setup and wipe up logs.

# TODO:- wipe out all logs and create
chat_manager.teardown()


# ########################******** END PHASE 4 ********##############################





