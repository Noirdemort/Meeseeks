from flask import Flask, request
import pymongo
import string
import random
from Crypto.PublicKey import RSA
from hashlib import sha512
import os

app = Flask(__name__)

# set up database

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["windfarm"]
users = db["users"]

# VARIABLE DECLARATION
verification_dict = {}

verification_key = "AI8RM-D3JKD-57UEW-EUYDE-0H684-3HXHW-WEF14-6DFS2-SJ97BS"


# setting up crypto keys
def sha512_hash(key):
    key_hash = sha512(key.encode("utf-8")).hexdigest()
    return key_hash


with open("key.pub", "r") as file:
    publicKey = RSA.importKey(file.read())

with open("key", "r") as file:
    privateKey = RSA.importKey(file.read())


@app.route("/proofOfIdentity/<username>", methods=["GET", "POST"])
def proving_identity(username):
    if request.method == "GET":
        # get hash of random string
        verifier = sha512_hash("".join([random.choice(string.ascii_letters) for _ in range(random.randint(25, 100))]))
        verification_dict[username] = verifier
        user_public_key = RSA.importKey(users.find_one({"username": username})["publicKey"])
        encrypted_data = list(user_public_key.encrypt(verifier.encode(), 2048)[0])
        return ",".join([str(x) for x in encrypted_data])
    else:
        encrypted_string = request.form.get("key")
        encrypted_data = encrypted_string.split(',')
        encrypted_data = bytes([int(x) for x in encrypted_data])
        users.update_one({"username": username}, {
            "$set": {
                "ip_address": request.remote_addr
            }
        })
        verified_private_key = privateKey.decrypt(encrypted_data).decode()
        if verified_private_key == verification_dict[username]:
            return "accountVerified"
        else:
            return "security breach"


@app.route("/verify", methods=["POST"])
def verification_user_client():
    encrypted_string = request.form.get("signature")
    encrypted_data = encrypted_string.split(',')
    encrypted_data = bytes([int(x) for x in encrypted_data])
    verified_public_key = privateKey.decrypt(encrypted_data).decode()
    if verified_public_key == verification_key:
        return "verified"
    else:
        return "client security breached"


@app.route("/store", methods=["POST"])
def store_user():
    username = request.form.get("user")
    username = username.split(",")
    username = bytes([int(x) for x in username])
    username = privateKey.decrypt(username).decode()
    rsa = request.form.get("rsa")
    user = {"username": username, "publicKey": rsa, "ipAddress": request.remote_addr}
    print(user)
    users.insert_one(user)
    return "secured"


@app.route("/unique", methods=["POST"])
def unique_username():
    username = request.form.get("user")
    username = username.split(",")
    username = bytes([int(x) for x in username])
    username = privateKey.decrypt(username).decode()
    if users.find_one({"username": username}):
        return "duplicate"
    else:
        return "unique"


@app.route("/delete", methods=["POST"])
def delete_account():
    username = request.form.get("user")
    username = username.split(",")
    username = bytes([int(x) for x in username])
    username = privateKey.decrypt(username).decode()
    users.delete_one({"username": username})
    return "deleted"


# redundant with unique
@app.route("/searchIndex", methods=["POST"])
def search_user():
    data = request.form.get("username")
    data = data.split(",")
    encrypted_data = bytes([int(x) for x in data])
    username = privateKey.decrypt(encrypted_data).decode()
    data = request.form.get("requester")
    data = data.split(",")
    encrypted_data = bytes([int(x) for x in data])
    requester = privateKey.decrypt(encrypted_data).decode()
    requester = users.find_one({"username": requester})
    user_public_key = RSA.importKey(requester["publicKey"])
    if users.find_one({"username": username}):
        return ",".join([str(x) for x in list(user_public_key.encrypt("onRecord".encode(), 2048)[0])])
    return ",".join([str(x) for x in list(user_public_key.encrypt("notFound".encode(), 2048)[0])])


@app.route("/getRSA", methods=["POST"])
def get_user_public_key():
    data = request.form.get("username")
    data = data.split(",")
    encrypted_data = bytes([int(x) for x in data])
    username = privateKey.decrypt(encrypted_data).decode()
    user = users.find_one({"username": username})
    return user['publicKey']


@app.route("/ipAddr", methods=["POST"])
def get_ip():
    data = request.form.get("username")
    data = data.split(",")
    encrypted_data = bytes([int(x) for x in data])
    username = privateKey.decrypt(encrypted_data).decode()
    data = request.form.get("requester")
    data = data.split(",")
    encrypted_data = bytes([int(x) for x in data])
    requester = privateKey.decrypt(encrypted_data).decode()
    requester = users.find_one({"username": requester})
    user_public_key = RSA.importKey(requester["publicKey"])
    user = users.find_one({"username": username})
    return ",".join([str(x) for x in list(user_public_key.encrypt(user["ipAddress"].encode(), 2048)[0])])


@app.route("/")
def hi():
    return "Hello, world!"


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
