//
//  CoreMethods.swift
//  EastWinds
//
//  Created by Noirdemort on 08/06/19.
//

import Foundation
import PythonKit
import CommonCrypto

class MainFrame {
    
    private let RemoteURL = "https://server.init/"
    
    let ServerPublicKey = "EMBED_KEY_HERE"
    
    let VerificationString = "AI8RM-D3JKD-57UEW-EUYDE-0H684-3HXHW-WEF14-6DFS2-SJ97BS"
    
    func post(portal: String, metadata: String) -> String {
        var response_back: String = "-1"
        let url = URL(string: "\(RemoteURL)/\(portal)/")!
        var request = URLRequest(url: url)
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpMethod = "POST"
        let postString = metadata
        request.httpBody = postString.data(using: .utf8)
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data, error == nil else {                                                 // check for fundamental networking error
                print("error=\(String(describing: error))")
                response_back = "-1"
                return
            }
            
            if let httpStatus = response as? HTTPURLResponse, httpStatus.statusCode != 200 {           // check for http errors
                print("statusCode should be 200, but is \(httpStatus.statusCode)")
                print("response = \(String(describing: response))")
            }
            
            let responseString = String(data: data, encoding: .utf8)
            print("responseString = \(String(describing: responseString))")
            response_back = String(describing: responseString)
        }
        task.resume()
        return response_back
    }
    
    
    func get(exfil: String)->String{
        let url = URL(string: RemoteURL+exfil)!
        var recdData = ""
        let task = URLSession.shared.dataTask(with: url) {(data, response, error) in
            guard let data = data else { return }
            recdData = String(data: data, encoding: .utf8)!
        }
        task.resume()
        return recdData
    }
}


class CommandLine {
    
    func getInput(fieldName: String)->String{
        print("[*] Enter \(fieldName): ")
        var reqdVariable = readLine()
        while reqdVariable == nil {
            print("[!] \(fieldName) is required.")
            print("[*] \(fieldName): ")
            reqdVariable = readLine()
        }
        return reqdVariable!
    }
    
    func getSecureInput(secField: String)->String{
        var buf = [CChar](repeating: 0, count: 8192)
        var secureData = readpassphrase("[#] Enter \(secField): ", &buf, buf.count, 0)
        while secureData == nil {
            print("[!] \(secField) is required.")
            secureData = readpassphrase("[#] Enter \(secField): ", &buf, buf.count, 0)
        }
        let secureString = String(validatingUTF8: secureData!)!
        return secureString
    }
    
}


class GhostProtocol {
    
    private let Random = Python.import("Crypto.Random")
    private let RSA = Python.import("Crypto.PublicKey.RSA")
    
    func encrypt(publicKey: String, message: String)->[Int]{
        let key = RSA.importKey(publicKey)
        let encryptedData = key.encrypt(Python.str(message).encode(), 1024)
        print(Python.list(encryptedData))
        return Array(Python.list(encryptedData))! as [Int]
    }
    
    static func intArrayToString(arr: [Int])->String{
        var exportString = ""
        for i in arr {
            exportString += "," + String(i)
        }
        return exportString
    }
    
    static func stringToIntArray(formattedString: String)->[Int]{
        let splittedSequence = formattedString.split(separator: ",")
        var encryptedData: [Int] = []
        for i in splittedSequence {
            encryptedData.append(Int(i)!)
        }
        return encryptedData
    }
    
    func decrypt(privateKey: String, encryptedData: [Int])->String{
        let encMsg = Python.bytes(encryptedData)
        let key = RSA.importKey(privateKey)
        let decryptedData = key.decrypt(encMsg).decode()
        print(decryptedData)
        return String(decryptedData)!
    }
    
    
    func correlatePair(publicKey: String, privateKey: String)->Int{
        let verifier = "fj6nd-37sn5-18ysd-yu65j-y9zjh"
        let encryption = self.encrypt(publicKey: publicKey, message: verifier)
        let decrypted = self.decrypt(privateKey: privateKey, encryptedData: encryption)
        if verifier == decrypted {
            return 1
        }
        return 0
    }
    
    
    func sha512(_ str: String) -> String? {
        guard
            let data = str.data(using: String.Encoding.utf8),
            let shaData = self.sha512conv(data)
            else { return nil }
        let rc = shaData.base64EncodedString(options: [])
        return rc
    }
    
    
    private func sha512conv(_ data: Data) -> Data? {
        guard let res = NSMutableData(length: Int(CC_SHA512_DIGEST_LENGTH)) else { return nil }
        CC_SHA512((data as NSData).bytes, CC_LONG(data.count), res.mutableBytes.assumingMemoryBound(to: UInt8.self))
        return res as Data
    }
   
    
    func randomInt()->Double{
        return Double(arc4random())
    }
    
    
    func symmetricEncrypt(){
        // implement later
    }
    
    
    func symmetricDecrypt(){
        // TODO
    }
    
}


class ChatSession {
    
    func server(){
        // use thread here to create a server
    }
    
    func listener(){
        // use thread and binding to connect to
    }
}


class User {
    
    let username: String
    let publicKey: String
    private let privateKey: String
    
    init(username: String, publicKey: String, privateKey: String) {
        self.username = username
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
    
    func accountVerification(){
        print("[*] Starting zero knowledge protocols...")
        let encryptedPhrase = centralServer.get(exfil: "proofOfIdentity")
        let encryptedData = GhostProtocol.stringToIntArray(formattedString: encryptedPhrase)
        print("[*] Decrypting using local keys...")
        let idDecrypted = ghost.decrypt(privateKey: self.privateKey, encryptedData: encryptedData)
        let serverSideProof = ghost.encrypt(publicKey: centralServer.ServerPublicKey, message: idDecrypted)
        print("[*] Packaging upload data...")
        let uploadData = GhostProtocol.intArrayToString(arr: serverSideProof)
        print("[*] Establishing Uplink...")
        print("[*] Uploading Data...")
        let response = centralServer.post(portal: "verifyUser", metadata: "key=\(uploadData)")
        if response != "accountVerified"{
            print("[!] Error: Poisoned User account!")
            print("[*] Exiting... ")
            exit(1)
        }
        print("[+] Account Verified.")
    }
}


