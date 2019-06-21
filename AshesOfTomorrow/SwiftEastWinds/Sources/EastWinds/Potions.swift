//
//  Potions.swift
//  EastWinds
//
//  Created by Noirdemort on 08/06/19.
//

import Foundation


func accountInterface()->Int{
    print("[*] Choose an action:")
    print("1. Login \n2. Sign-up \n3. Delete Account")
    print("Example: Enter 1 for Login")
    let choice = cmdInterface.getInput(fieldName: "Account action code")
    if (["1", "2", "3"].contains(choice)) {
        return Int(choice)!
    } else {
        return 0
    }
}
