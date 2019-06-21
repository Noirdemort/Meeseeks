import Foundation
import PythonKit
//import SocketIO

// declaration and initialization
let centralServer = MainFrame()
let cmdInterface = CommandLine()
let ghost = GhostProtocol()


// #######################******** START PHASE 0 ********##############################

// verify local public key with server

print("[*] Verifiying local data...")

let signature = ghost.encrypt(publicKey: centralServer.ServerPublicKey, message: centralServer.VerificationString)

print("[*] Intializing encryption protocols... ")

let exportSignature = GhostProtocol.intArrayToString(arr: signature)

print("[*] Uploading Signature...")
let verification = centralServer.post(portal: "verify", metadata: "sign=\(exportSignature)")

if verification != "verified" {
    print("[!] Verification failed!")
    print("[!] Invalid Public Key. Try updating.")
    exit(1)
}

print("[+] Signature Verified.")

//  #######################******** END PHASE 0 ********##############################



// TODO:- registration phase - p2p based registartion



// #######################******** START PHASE 1 ********##############################

let initAction = accountInterface()

if initAction == 0 {
    print("[*] Unaccountable behaviour detected!")
    print("[!] Exiting...")
    exit(1)
}

private let username = cmdInterface.getInput(fieldName: "username")
private let publicKey = cmdInterface.getInput(fieldName: "RSA Public Key")
private let privateKey = cmdInterface.getSecureInput(secField: "RSA Private Key [kept locally]")

let user = User(username: username, publicKey: publicKey, privateKey: privateKey)

print("[*] Preparing encryption cache... ")
let uniqueData = ghost.encrypt(publicKey: centralServer.ServerPublicKey, message: user.username)
let uniquenessCheckEncryptedField = GhostProtocol.intArrayToString(arr: uniqueData)

switch (initAction) {
case 1:
    user.accountVerification()
    break;
case 2:
    // registration
    
    // check uniqueness
    print("[*] Verifying public key... ")
    
    let unique = centralServer.post(portal: "unique", metadata: "user=\(uniquenessCheckEncryptedField)")
    if unique != "unique" {
        print("[!] Error - Public Key already exists.")
        exit(1)
    }
    
    let pairCompatible = ghost.correlatePair(publicKey: user.publicKey, privateKey: privateKey)
    if pairCompatible != 1 {
        print("[!] Error: Breached RSA Pairs.")
        print("[*] Exiting...")
        exit(1)
    }
    
    print("[*] Establishing uplink and storing username and public key")
    
    let idSignature = ghost.encrypt(publicKey: centralServer.ServerPublicKey, message: "\(user.username)&\(user.publicKey)")
    let uploadSignature = GhostProtocol.intArrayToString(arr: idSignature)
    
    let uploadVerification = centralServer.post(portal: "store", metadata: "data=\(uploadSignature)")
    
    if uploadVerification != "secured" {
        print("[!] Error: Identification Signature storage failure.")
        print("Exiting...")
        exit(1)
    }
    
    print("[+] Account successfully created!")
    
    // upload data to server
    
    break;
case 3:
    user.accountVerification()
    let accountStatus = centralServer.post(portal: "delete", metadata: "user=\(uniquenessCheckEncryptedField)")
    if accountStatus == "deleted" {
        print("[-] Account Deleted.")
        print("[*] Exiting...")
        exit(0)
    }else {
        print("[!] Account Deletion Unsuccessfull! Try again.")
        exit(1)
    }
    break;
default:
    print("[!] Unrecognizable behaviour detected.")
    print("[*] Exiting...")
    exit(1);
}

print("[+] Identity shield activated.")


// END:- server knows about my online status

// #######################******** END PHASE 1 ********##############################



// #######################******** START PHASE 2 ********##############################


// Start local server
DispatchQueue.global(qos: .userInitiated).async {
    
    DispatchQueue.main.sync {
        print("[+] Local Server started and listening on http://0.0.0.0:42042/ ...")
    }
}


// #######################******** END PHASE 2 ********##############################


// #######################******** START PHASE 3 ********##############################

// Query User & Initiate session with selected host

// #######################******** END PHASE 3 ********##############################



// #######################******** END PHASE 4 ********##############################

// full fledged session

// #######################******** END PHASE 4 ********##############################



// #######################******** START PHASE 5 ********##############################

// tear down the whole setup and wipe up logs.

// #######################******** END PHASE 5 ********##############################

let cryptoRandom = Python.import("this")
print(cryptoRandom.c)



