//
//  StickProtocolModule.swift
//  STiiiCK
//
//  Created by Omar Basem on 10/08/2020.
//  Copyright © 2020 STiiiCK. All rights reserved.
//

import Foundation
import SimpleKeychain
import CommonCrypto
import CryptoSwift
import SignalArgon2

public class SP {

    var db: YapDatabase?
    var service: String?
    var accessGroup: String?
    public init(service: String, accessGroup: String, db: YapDatabase) {
        self.db = db
        self.service = service
        self.accessGroup = accessGroup
    }

    public func initialize(userId: String, password: String, progressEvent: (([String: Any]) -> Void)?) -> [String: Any] {
        let keychain = A0SimpleKeychain(service: self.service!, accessGroup: self.accessGroup!)
        keychain.setString(password, forKey: "password")

        // Generate password salt
        let passwordSalt = generateRandomBytes(count: 32)
        // Hashing password
        let (passwordHash, _) = try! Argon2.hash(iterations: 3, memoryInKiB: 4 * 1024, threads: 2, password: password.data(using: .utf8)!, salt: passwordSalt!, desiredLength: 32, variant: .id, version: .v13)

        UserDefaults(suiteName: self.accessGroup!)!.set(userId, forKey: "userId")
        let databaseConnection = db!.newConnection()
        let encryptionManager = try? EncryptionManager(accountKey: userId, databaseConnection: databaseConnection)

        let identityKey = encryptionManager?.storage.getIdentityKeyPair()
        let signedPreKey = encryptionManager!.keyHelper()?.generateSignedPreKey(withIdentity: identityKey!, signedPreKeyId: 0)
        let currentTime = Date().timestamp
        UserDefaults(suiteName: self.accessGroup!)!.set(signedPreKey?.preKeyId, forKey: "activeSignedPreKeyId")
        UserDefaults(suiteName: self.accessGroup!)!.set(currentTime, forKey: "activeSignedPreKeyTimestamp")
        encryptionManager!.storage.storeSignedPreKey((signedPreKey?.serializedData())!, signedPreKeyId: signedPreKey!.preKeyId)
        let preKeys = encryptionManager?.generatePreKeys(0, count: 10)

        var preKeysArray = [[String: Any]]()
        var counter = 0;
        for preKey in preKeys! {
            if (counter > 0) {
                var map = [String: Any]()
                map["id"] = preKey.preKeyId
                map["public"] = preKey.keyPair?.publicKey.base64EncodedString()
                let cipherMap = pbEncrypt(text: preKey.keyPair!.privateKey, pass: password)
                map["cipher"] = cipherMap["cipher"]!
                map["salt"] = cipherMap["salt"]!
                preKeysArray.append(map)
            }
            counter += 1;
            if (progressEvent != nil) {
                progressEvent!(["progress": counter, "total": preKeys!.count])
            } else {
                print("Printing progress because progress event is null", counter)
            }
        }

        var signedMap = [String: Any]()
        signedMap["id"] = signedPreKey?.preKeyId
        signedMap["public"] = signedPreKey?.keyPair?.publicKey.base64EncodedString()
        signedMap["signature"] = signedPreKey?.signature.base64EncodedString()
        let signedCipherMap = pbEncrypt(text: (signedPreKey?.keyPair!.privateKey)!, pass: password)
        signedMap["cipher"] = signedCipherMap["cipher"]!
        signedMap["salt"] = signedCipherMap["salt"]!


        var identityMap = [String: Any]()
        identityMap["public"] = identityKey!.publicKey.base64EncodedString()
        let identityCipherMap = pbEncrypt(text: identityKey!.privateKey, pass: password)
        identityMap["cipher"] = identityCipherMap["cipher"]!
        identityMap["salt"] = identityCipherMap["salt"]!
        identityMap["localId"] = encryptionManager?.registrationId

        let oneTimeId = UUID().uuidString.lowercased()
        var map = [String: Any]()
        map["identityKey"] = identityMap
        map["signedPreKey"] = signedMap
        map["preKeys"] = preKeysArray
        map["oneTimeId"] = oneTimeId
        map["passwordHash"] = passwordHash.base64EncodedString()
        map["passwordSalt"] = passwordSalt?.base64EncodedString()

        let signalProtocolAddress = SignalAddress(name: userId, deviceId: 0)
        do {
            let sessionBuilder = SessionBuilder(address: signalProtocolAddress, context: encryptionManager!.signalContext)
            var preKeyBundle: PreKeyBundle?
            preKeyBundle = try PreKeyBundle(registrationId: encryptionManager!.registrationId, deviceId: 1, preKeyId: preKeys![0].preKeyId, preKeyPublic: preKeys![0].keyPair!.publicKey, signedPreKeyId: signedPreKey!.preKeyId, signedPreKeyPublic: (signedPreKey?.keyPair!.publicKey)!, signature: signedPreKey!.signature, identityKey: identityKey!.publicKey)
            try sessionBuilder.processPreKeyBundle(preKeyBundle!)
        } catch {
            print("Error info bundle: \(error)")
        }
        return map
    }

    public func reInit(bundle: Dictionary<String, Any>, password: String, oneTimeId: String, progressEvent: (([String: Any]) -> Void)?) {
        //  ** Regenerate previous keys  ** //
        let keychain = A0SimpleKeychain(service: self.service!, accessGroup: self.accessGroup!)
        keychain.setString(password, forKey: "password")
        let userId = bundle["userId"] as! String
        let myId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
        UserDefaults(suiteName: self.accessGroup!)!.set(userId, forKey: "userId")
        let databaseConnection = db!.newConnection()
        let encryptionManager = try? EncryptionManager(accountKey: userId, databaseConnection: databaseConnection)

        let publicKey = Data(base64Encoded: bundle["identityPublic"] as! String)
        let privateKey = pbDecrypt(encryptedIvText: bundle["identityCipher"] as! String, salt: bundle["identitySalt"] as! String, pass: password)
        let identityKeyPair = try! IdentityKeyPair(publicKey: publicKey!, privateKey: privateKey)
        encryptionManager?.storage.saveIdenityKeyPair(keyPair: identityKeyPair, regId: bundle["localId"] as! UInt32)


        let signedPreKeys = bundle["signedPreKeys"] as! [Dictionary<String, Any>]
        let preKeys = bundle["preKeys"] as! [Dictionary<String, Any>]
        let senderKeys = bundle["senderKeys"] as! [Dictionary<String, Any>]
        var count = 1
        let totalKeys = signedPreKeys.count + preKeys.count + senderKeys.count

        for key in signedPreKeys {
            let SPKPub = Data(base64Encoded: key["public"] as! String)
            let SPKPriv = pbDecrypt(encryptedIvText: key["cipher"] as! String, salt: key["salt"] as! String, pass: password)
            let keyPair = try! KeyPair(publicKey: SPKPub!, privateKey: SPKPriv)
            let signedPreKey = encryptionManager!.keyHelper()?.createSignedPreKey(withKeyId: key["id"] as! UInt32, keyPair: keyPair, signature: Data(base64Encoded: key["signature"] as! String)!)
            encryptionManager!.storage.storeSignedPreKey((signedPreKey?.serializedData())!, signedPreKeyId: signedPreKey!.preKeyId)
            if (key["active"] as! Bool == true) {
                UserDefaults(suiteName: self.accessGroup!)!.set(signedPreKey?.preKeyId, forKey: "activeSignedPreKeyId")
                UserDefaults(suiteName: self.accessGroup!)!.set(key["timestamp"], forKey: "activeSignedPreKeyTimestamp")
            }
            count += 1
            if (progressEvent != nil) {
                progressEvent!(["progress": count, "total": totalKeys])
            } else {
                print("Printing progress because progress event is null", count)
            }
        }

        for key in preKeys {
            let prePubKey = Data(base64Encoded: key["public"] as! String)
            let prePrivKey = pbDecrypt(encryptedIvText: key["cipher"] as! String, salt: key["salt"] as! String, pass: password)
            let keyPair = try! KeyPair(publicKey: prePubKey!, privateKey: prePrivKey)
            let preKey = encryptionManager!.keyHelper()?.createPreKey(withKeyId: key["id"] as! UInt32, keyPair: keyPair)
            encryptionManager!.storage.storePreKey(preKey!.serializedData()!, preKeyId: preKey!.preKeyId)
            count += 1
            if (progressEvent != nil) {
                progressEvent!(["progress": count, "total": totalKeys])
            } else {
                print("Printing progress because progress event is null", count)
            }
        }

        // OWN SENDER KEYS
        let signalProtocolAddress = SignalAddress(name: userId, deviceId: 1)
        var skc = 0
        for key in senderKeys {
            print("DECRYPT A SENDERKEY", skc)
            print("senderkey", key)
            skc += 1
            reinitSenderKey(key: key, signalProtocolAddress: signalProtocolAddress, userId: userId, encryptionManager: encryptionManager!)
            // send progress event
            count += 1
            if (progressEvent != nil) {
                progressEvent!(["progress": count, "total": totalKeys])
            } else {
                print("Printing progress because progress event is null", count)
            }
        }
        // *** //
    }

    public func createPasswordHash(password: String, salt: String) -> String {
        let (passwordHash, _) = try! Argon2.hash(iterations: 3, memoryInKiB: 4 * 1024, threads: 2, password: password.data(using: .utf8)!, salt: Data(base64Encoded: salt)!, desiredLength: 32, variant: .id, version: .v13)
        return passwordHash.base64EncodedString()
    }

    public func refreshSignedPreKey(days: Int) -> [String: Any]? {
//        let signedPreKeyAge = days * 24 * 60 * 60
        let signedPreKeyAge = 60
        let userId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
        let databaseConnection = db!.newConnection()
        let currentTime = Date().timestamp
        let activeSPKTimestamp = Int64(UserDefaults(suiteName: self.accessGroup!)!.integer(forKey: "activeSignedPreKeyTimestamp"))
        let activeDuration = currentTime - activeSPKTimestamp
        if (activeDuration > signedPreKeyAge) {
            let activeSPKId = Int64(UserDefaults(suiteName: self.accessGroup!)!.integer(forKey: "activeSignedPreKeyTimestamp"))
            let encryptionManager = try? EncryptionManager(accountKey: userId!, databaseConnection: databaseConnection)
            let identityKey = encryptionManager?.storage.getIdentityKeyPair()
            let signedPreKey = encryptionManager!.keyHelper()?.generateSignedPreKey(withIdentity: identityKey!, signedPreKeyId: UInt32(activeSPKId) + 1)
            UserDefaults(suiteName: self.accessGroup!)!.set(signedPreKey?.preKeyId, forKey: "activeSignedPreKeyId")
            UserDefaults(suiteName: self.accessGroup!)!.set(currentTime, forKey: "activeSignedPreKeyTimestamp")

            let keychain = A0SimpleKeychain(service: self.service!, accessGroup: self.accessGroup!)
            let password: String = keychain.string(forKey: "password")!
            var signedMap = [String: Any]()
            signedMap["id"] = signedPreKey?.preKeyId
            signedMap["public"] = signedPreKey?.keyPair?.publicKey.base64EncodedString()
            signedMap["signature"] = signedPreKey?.signature.base64EncodedString()
            let signedCipherMap = pbEncrypt(text: (signedPreKey?.keyPair!.privateKey)!, pass: password)
            signedMap["cipher"] = signedCipherMap["cipher"]!
            signedMap["salt"] = signedCipherMap["salt"]!
            return signedMap
        }
        return nil
    }

    public func resetDatabase() {
        let databaseConnection = db!.newConnection()
        databaseConnection.readWrite { (transaction) in
            transaction.removeAllObjectsInAllCollections()
        }
        UserDefaults.resetStandardUserDefaults() // TODO: CHECK RESETING IS DONE
    }

    public func initPairwiseSession(bundle: Dictionary<String, Any>) {
        do {
            let userId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
            let databaseConnection = db!.newConnection()
            let encryptionManager = try? EncryptionManager(accountKey: userId!, databaseConnection: databaseConnection)
            let signalProtocolAddress = SignalAddress(name: bundle["userId"] as! String, deviceId: bundle["deviceId"] as! Int32)
            let sessionBuilder = SessionBuilder(address: signalProtocolAddress, context: encryptionManager!.signalContext)
            let preKey = Data(base64Encoded: bundle["preKey"] as! String)
            let signedPreKey = Data(base64Encoded: bundle["signedPreKey"] as! String)
            let identityKey = Data(base64Encoded: bundle["identityKey"] as! String)
            let signature = Data(base64Encoded: bundle["signature"] as! String)
            let preKeyBundle = try PreKeyBundle(registrationId: bundle["localId"] as! UInt32, deviceId: bundle["deviceId"] as! UInt32, preKeyId: bundle["preKeyId"] as! UInt32, preKeyPublic: preKey!, signedPreKeyId: bundle["signedPreKeyId"] as! UInt32, signedPreKeyPublic: signedPreKey!, signature: signature!, identityKey: identityKey!)
            try sessionBuilder.processPreKeyBundle(preKeyBundle)
        } catch {
            print("ERROR IN INIT SESSION: \(error)")
        }
    }

    public func pairwiseSessionExists(oneTimeId: String) -> Bool? {
        let myId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
        let databaseConnection = db!.newConnection()
        let encryptionManager = try? EncryptionManager(accountKey: myId!, databaseConnection: databaseConnection)
        let signalProtocolAddress = SignalAddress(name: oneTimeId, deviceId: 0)
        let exists = encryptionManager?.storage.sessionRecordExists(for: signalProtocolAddress)
        return exists
    }


    public func encryptTextPairwise(userId: String, deviceId: Int32, text: String) -> String? {
        do {
            let myId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
            let databaseConnection = db!.newConnection()
            let encryptionManager = try? EncryptionManager(accountKey: myId!, databaseConnection: databaseConnection)
            let signalProtocolAddress = SignalAddress(name: userId, deviceId: deviceId)
            let sessionCipher = SessionCipher(address: signalProtocolAddress, context: encryptionManager!.signalContext)
            let cipher = try sessionCipher.encryptData(text.data(using: .utf8)!)
            return cipher.data.base64EncodedString()
        } catch {
            print("ERROR IN ENCRYPT TEXT: \(error)")
        }
        return nil
    }

    public func decryptTextPairwise(senderId: String, deviceId: Int32, cipher: String, isSelf: Bool) -> String? {
        do {
            let myId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
            let databaseConnection = db!.newConnection()
            let encryptionManager = try? EncryptionManager(accountKey: myId!, databaseConnection: databaseConnection)
            let signalProtocolAddress = SignalAddress(name: senderId, deviceId: deviceId)
            let sessionCipher = SessionCipher(address: signalProtocolAddress, context: encryptionManager!.signalContext)
            var signalCiphertext: SignalCiphertext?
            signalCiphertext = SignalCiphertext(data: Data(base64Encoded: cipher)!, type: SignalCiphertextType.unknown)
            let decryptedBytes = try sessionCipher.decryptCiphertext(signalCiphertext!)
            return String(decoding: decryptedBytes, as: UTF8.self)
        } catch {
            print("ERROR IN DECRYPT TEXT: \(error)")
            return nil
        }
    }

    public func encryptText(userId: String, stickId: String, text: String, isSticky: Bool) -> String? {
        do {
            let myId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
            let databaseConnection = db!.newConnection()
            let encryptionManager = try? EncryptionManager(accountKey: myId!, databaseConnection: databaseConnection)
            let signalProtocolAddress = SignalAddress(name: userId, deviceId: isSticky ? 1 : 0)
            let senderKeyName = SenderKeyName(groupId: stickId, address: signalProtocolAddress)

            let senderKeyData = encryptionManager?.storage.loadSenderKey(for: senderKeyName)
            let senderKey = try SenderKeyRecord(data: senderKeyData!, context: encryptionManager!.signalContext)
            let groupCipher = GroupCipher(senderKeyName: senderKeyName, context: encryptionManager!.signalContext)
            let cipher = try groupCipher.encryptData(text.data(using: .utf8)!, isSticky: isSticky)
            return cipher.data.base64EncodedString()
        } catch {
            print("ERROR IN ENCRYPT GROUP TEXT: \(error)")
            return nil
        }
    }

    public func getChainStep(userId: String, stickId: String) -> UInt32? {
        do {
            let myId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
            let databaseConnection = db!.newConnection()
            let encryptionManager = try? EncryptionManager(accountKey: myId!, databaseConnection: databaseConnection)
            let signalProtocolAddress = SignalAddress(name: userId, deviceId: 1)
            let senderKeyName = SenderKeyName(groupId: stickId, address: signalProtocolAddress)
            let senderKeyData = encryptionManager?.storage.loadSenderKey(for: senderKeyName)
            let senderKey = try SenderKeyRecord(data: senderKeyData!, context: encryptionManager!.signalContext)
            let step = senderKey.getChainStep()
            return step
        } catch {
            print("ERROR IN GET CHAIN STEP: \(error)")
            return nil
        }
    }

    public func ratchetChain(stickId: String, steps: Int32) {
        let userId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")!
        let databaseConnection = db!.newConnection()
        let encryptionManager = try? EncryptionManager(accountKey: userId, databaseConnection: databaseConnection)
        let signalProtocolAddress = SignalAddress(name: userId, deviceId: 1)
        let senderKeyName = SenderKeyName(groupId: stickId, address: signalProtocolAddress)
        let groupCipher = GroupCipher(senderKeyName: senderKeyName, context: encryptionManager!.signalContext)
        groupCipher.ratchetChain(steps)
    }


    public func decryptText(senderId: String, stickId: String, cipher: String, isSticky: Bool) -> String? {
        if (cipher.count < 4) {
            return nil
        }
        do {
            let myId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
            let isSelf = myId == senderId
            let databaseConnection = db!.newConnection()
            let encryptionManager = try? EncryptionManager(accountKey: myId!, databaseConnection: databaseConnection)
            let signalProtocolAddress = SignalAddress(name: senderId, deviceId: isSticky ? 1 : 0)
            let senderKeyName = SenderKeyName(groupId: stickId, address: signalProtocolAddress)
            let groupCipher = GroupCipher(senderKeyName: senderKeyName, context: encryptionManager!.signalContext)
            let cipherText = SignalCiphertext(data: Data(base64Encoded: cipher)!, type: SignalCiphertextType.senderKeyMessage)
            let decryptedBytes = try groupCipher.decryptCiphertext(cipherText, isSticky: isSticky, isSelf: isSelf)
            return String(decoding: decryptedBytes, as: UTF8.self)
        } catch {
            print("ERROR IN DECRYPT GROUP TEXT: \(error)")
            return nil
        }
    }

    public func initSession(senderId: String, stickId: String, cipherSenderKey: String?, isSticky: Bool) {
        if (cipherSenderKey != nil) {
            do {
                let myId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
                let databaseConnection = db!.newConnection()
                let encryptionManager = try? EncryptionManager(accountKey: myId!, databaseConnection: databaseConnection)
                let signalProtocolAddress = SignalAddress(name: senderId, deviceId: isSticky ? 1 : 0)
                let senderKeyName = SenderKeyName(groupId: stickId, address: signalProtocolAddress)
                let groupSesisonBuilder = GroupSessionBuilder(context: encryptionManager!.signalContext)
                let senderKey = decryptTextPairwise(senderId: senderId, deviceId: isSticky ? 1 : 0, cipher: cipherSenderKey!, isSelf: false)
                if (senderKey != nil) {
                    let senderKeyDistributionMessage = try SenderKeyDistributionMessage(data: Data(base64Encoded: senderKey!)!, context: encryptionManager!.signalContext)
                    try groupSesisonBuilder.processSession(with: senderKeyName, senderKeyDistributionMessage: senderKeyDistributionMessage)
                }
            } catch {
                print("ERROR IN INTI GROUP SENDER SESSION: \(error)")
            }
        }
    }

    public func getSenderKey(senderId: String, targetId: String, stickId: String, isSticky: Bool) -> String? {
        let databaseConnection = db!.newConnection()
        var distributionMessage: String?
        if (isSticky) {
            databaseConnection.read { (transaction) in
                distributionMessage = transaction.object(forKey: stickId, inCollection: "StickyKey") as? String
            }
        } else {
            let myId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
            let databaseConnection = db!.newConnection()
            let encryptionManager = try? EncryptionManager(accountKey: myId!, databaseConnection: databaseConnection)
            let signalProtocolAddress = SignalAddress(name: senderId, deviceId: isSticky ? 1 : 0)
            let senderKeyName = SenderKeyName(groupId: stickId, address: signalProtocolAddress)
            let groupSessionBuilder = GroupSessionBuilder(context: encryptionManager!.signalContext)
            distributionMessage = try! groupSessionBuilder.createSession(with: senderKeyName).serializedData().base64EncodedString()
        }
        let cipherText = encryptTextPairwise(userId: targetId, deviceId: isSticky ? 1 : 0, text: distributionMessage!)
        return cipherText
    }


    public func getEncryptingSenderKey(userId: String, stickId: String, isSticky: Bool) -> Dictionary<String, Any>? {
        do {
            let myId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
            let databaseConnection = db!.newConnection()
            let encryptionManager = try? EncryptionManager(accountKey: myId!, databaseConnection: databaseConnection)
            let signalProtocolAddress = SignalAddress(name: userId, deviceId: isSticky ? 1 : 0)
            let senderKeyName = SenderKeyName(groupId: stickId, address: signalProtocolAddress)
            let groupSessionBuilder = GroupSessionBuilder(context: encryptionManager!.signalContext)
            let distributionMessage = try groupSessionBuilder.createSession(with: senderKeyName)
            databaseConnection.readWrite { (transaction) in
                transaction.setObject(distributionMessage.serializedData().base64EncodedString(), forKey: stickId, inCollection: "StickyKey")
            }
            let senderKeyData = encryptionManager?.storage.loadSenderKey(for: senderKeyName)
            let senderKey = try SenderKeyRecord(data: senderKeyData!, context: encryptionManager!.signalContext)
            let cipher = encryptTextPairwise(userId: userId, deviceId: isSticky ? 1 : 0, text: senderKey.getSKSPrivateKey().base64EncodedString())
            var map = [String: Any]()
            map["id"] = senderKey.getSKSId()
            map["chainKey"] = senderKey.getSKSChainKey().base64EncodedString()
            map["public"] = senderKey.getSKSPublicKey().base64EncodedString()
            map["cipher"] = cipher
            return map
        } catch {
            print("ERROR IN GET ENCRYPTING SENDER KEYEXEC: \(error)")
        }
        return nil
    }


    public func isSessionEmpty(senderId: String, stickId: String, isSticky: Bool) -> Bool {
        do {
            let myId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
            let databaseConnection = db!.newConnection()
            let encryptionManager = try? EncryptionManager(accountKey: myId!, databaseConnection: databaseConnection)
            let signalProtocolAddress = SignalAddress(name: senderId, deviceId: isSticky ? 1 : 0)
            let senderKeyName = SenderKeyName(groupId: stickId, address: signalProtocolAddress)
            let senderKeyData = encryptionManager?.storage.loadSenderKey(for: senderKeyName)
            let senderKey = try SenderKeyRecord(data: senderKeyData!, context: encryptionManager!.signalContext)
            return senderKey.isEmpty()
        } catch {
            print("ERROR IN IS SESSION EMPTY: \(error)")
            return false
        }
    }

    public func reinitSenderKey(key: Dictionary<String, Any>, signalProtocolAddress: SignalAddress, userId: String, encryptionManager: EncryptionManager) {
        let senderKeyName = SenderKeyName(groupId: key["stickId"] as! String, address: signalProtocolAddress)
        let senderPubKey = Data(base64Encoded: key["public"] as! String)
        let cipher = decryptTextPairwise(senderId: userId, deviceId: 1, cipher: key["cipher"] as! String, isSelf: true)
        let senderPrivKey = Data(base64Encoded: cipher!)
        let signedSenderKey = try! KeyPair(publicKey: senderPubKey!, privateKey: senderPrivKey!)
        let senderKeyRecord = try! SenderKeyRecord(context: encryptionManager.signalContext)
        senderKeyRecord.setSenderKeyStateWithKeyId(key["id"] as! UInt32, chainKey: Data(base64Encoded: key["chainKey"] as! String)!, sigKeyPair: signedSenderKey)
        encryptionManager.storage.storeSenderKey(senderKeyRecord.serializedData()!, senderKeyName: senderKeyName)

        // STORE INITIAL SENDER KEY
        let groupSessionBuilder = GroupSessionBuilder(context: encryptionManager.signalContext)
        let distributionMessage = try! groupSessionBuilder.createSession(with: senderKeyName)
        let databaseConnection = db!.newConnection()
        databaseConnection.readWrite { (transaction) in
            transaction.setObject(distributionMessage.serializedData().base64EncodedString(), forKey: key["stickId"] as! String, inCollection: "StickyKey")
        }

        // RATCHET CHAIN
        let groupCipher = GroupCipher(senderKeyName: senderKeyName, context: encryptionManager.signalContext)
        groupCipher.ratchetChain(key["step"] as! Int32)
    }

    public func reinitMyStickySession(key: Dictionary<String, Any>) {
        let userId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")!
        let databaseConnection = db!.newConnection()
        let encryptionManager = try? EncryptionManager(accountKey: userId, databaseConnection: databaseConnection)
        let signalProtocolAddress = SignalAddress(name: userId, deviceId: 1)
        reinitSenderKey(key: key, signalProtocolAddress: signalProtocolAddress, userId: userId, encryptionManager: encryptionManager!)
    }

    public func sessionExists(senderId: String, stickId: String, isSticky: Bool) -> Bool? {
        let exists = !isSessionEmpty(senderId: senderId, stickId: stickId, isSticky: isSticky)
        return exists
    }

    // TODO: background
    public func generatePreKeys(nextPreKeyId: UInt, count: UInt) -> [[String: Any]] {
        let myId = UserDefaults(suiteName: self.accessGroup!)!.string(forKey: "userId")
        let keychain = A0SimpleKeychain(service: self.service!, accessGroup: self.accessGroup!)
        let password: String = keychain.string(forKey: "password")!
        let databaseConnection = self.db!.newConnection()
        let encryptionManager = try? EncryptionManager(accountKey: myId!, databaseConnection: databaseConnection)
        let preKeys = encryptionManager?.generatePreKeys(nextPreKeyId, count: count)
        var preKeysArray = [[String: Any]]()
        for preKey in preKeys! {
            var map = [String: Any]()
            map["id"] = preKey.preKeyId
            map["public"] = preKey.keyPair?.publicKey.base64EncodedString()
            let cipherMap = self.pbEncrypt(text: preKey.keyPair!.privateKey, pass: password)
            map["cipher"] = cipherMap["cipher"]!
            map["salt"] = cipherMap["salt"]!
            preKeysArray.append(map)
        }
        return preKeysArray
    }

    public func encryptMedia(filePath: String, contentType: String?) -> Dictionary<String, String>? {
        do {
            let fileData = NSData(contentsOfFile: filePath)
            var nsEncryptionKey = NSData()
            var nsDigest = NSData()
            let encryptedData = FileCrypto.encryptFileData(fileData! as Data, shouldPad: true, outKey: &nsEncryptionKey, outDigest: &nsDigest)
            let encryptionKey = nsEncryptionKey as Data
            let digest = nsDigest as Data
            let encryptedFilePath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.appendingPathComponent(UUID().uuidString.lowercased())
            try encryptedData?.write(to: encryptedFilePath!)
            let secret = encryptionKey.base64EncodedString() + digest.base64EncodedString()
            var map = [String: String]()
            map["uri"] = encryptedFilePath!.absoluteString
            map["secret"] = secret
            return map;
        } catch {
            print("ERROR IN ENCRYPT MEDIA: \(error)")
        }
        return nil;
    }

    public func encryptMedia(fileData: Data, contentType: String?) -> Dictionary<String, String>? {
        do {
            var nsEncryptionKey = NSData()
            var nsDigest = NSData()
            let encryptedData = FileCrypto.encryptFileData(fileData, shouldPad: true, outKey: &nsEncryptionKey, outDigest: &nsDigest)
            let encryptionKey = nsEncryptionKey as Data
            let digest = nsDigest as Data
            let encryptedFilePath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.appendingPathComponent(UUID().uuidString.lowercased())
            try encryptedData?.write(to: encryptedFilePath!)
            let secret = encryptionKey.base64EncodedString() + digest.base64EncodedString()
            var map = [String: String]()
            map["uri"] = encryptedFilePath!.absoluteString
            map["secret"] = secret
            return map;
        } catch {
            print("ERROR IN ENCRYPT MEDIA: \(error)")
        }
        return nil;
    }

    public func encryptFilePairwise(userId: String, filePath: String, contentType: String) -> [String: String] {
        let hashMap = encryptMedia(filePath: filePath, contentType: contentType)
        let cipherText = encryptTextPairwise(userId: userId, deviceId: 0, text: hashMap!["secret"]!)
        var map = [String: String]()
        map["uri"] = hashMap!["uri"]
        map["cipher"] = cipherText
        return map
    }

    public func encryptFile(senderId: String, stickId: String, filePath: String, contentType: String, isSticky: Bool) -> [String: String] {
        let hashMap = encryptMedia(filePath: filePath, contentType: contentType)
        let cipherText = encryptText(userId: senderId, stickId: stickId, text: hashMap!["secret"]!, isSticky: isSticky)
        var map = [String: String]()
        map["uri"] = hashMap!["uri"]
        map["cipher"] = cipherText
        return map
    }

    public func decryptMedia(filePath: String, secret: String, size: NSInteger, outputPath: String) -> String? {
        do {
            let fileData = NSData(contentsOfFile: filePath)
            let key = secret[0...87]
            let digest = secret[88...(secret.count - 1)]
            let decryptedData = try FileCrypto.decryptFile(fileData! as Data, withKey: Data(base64Encoded: key)!, digest: Data(base64Encoded: digest)!, unpaddedSize: UInt32(size))
            let outputUrl = URL(fileURLWithPath: outputPath)
            try decryptedData.write(to: outputUrl)
            return "file://" + outputPath;
        } catch {
            print("ERROR IN DECRYPT MEDIA: \(error)")
        }
        return nil
    }


    public func decryptFilePairwise(senderId: String, filePath: String, cipher: String, size: NSInteger, outputPath: String) -> String? {
        let secret = decryptTextPairwise(senderId: senderId, deviceId: 0, cipher: cipher, isSelf: false)
        var path: String? = nil
        if (secret != nil) {
            path = decryptMedia(filePath: filePath, secret: secret!, size: size, outputPath: outputPath)
        }
        return path
    }

    public func decryptFile(senderId: String, stickId: String, filePath: String, cipher: String, size: NSInteger, outputPath: String, isSticky: Bool) -> String? {
        let secret = decryptText(senderId: senderId, stickId: stickId, cipher: cipher, isSticky: isSticky)
        var path: String? = nil
        if (secret != nil) {
            path = decryptMedia(filePath: filePath, secret: secret!, size: size, outputPath: outputPath)
        }
        return path
    }

    public func generateRandomBytes(count: NSInteger) -> Data? {
        var keyData = Data(count: count)
        let result = keyData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        if result == errSecSuccess {
            return keyData
        } else {
            print("Problem generating random bytes")
            return nil
        }
    }

    public func pbkdf2Derivation(password: Data, salt: Data, iterations: UInt32, outputLength: Int) -> [UInt8] {
        let passwordBytes: [Int8] = password.withUnsafeBytes {
            [Int8]($0.bindMemory(to: Int8.self))
        }
        let saltBytes: [UInt8] = salt.withUnsafeBytes { [UInt8]($0) }
        var outputBytes = [UInt8](repeating: 0, count: outputLength)
        let status = CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            passwordBytes,
            passwordBytes.count,
            saltBytes,
            saltBytes.count,
            CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256),
            iterations,
                &outputBytes,
            outputBytes.count
        )

        return outputBytes
    }

    public func pbEncrypt(text: Data, pass: String) -> Dictionary<String, String?> {
        // Generate salt
        let salt = generateRandomBytes(count: 32)

        // Generating IV.
        let ivSize = 16;
        let iv = generateRandomBytes(count: ivSize)

        // Hashing key.
//    let (rawHash, _) = try! Argon2.hash(iterations: 1, memoryInKiB: 1 * 1024, threads: 2, password: pass.data(using: .utf8)!, salt: salt!, desiredLength: 32, variant: .id, version: .v13)
        let (rawHash, _) = try! Argon2.hash(iterations: 3, memoryInKiB: 4 * 1024, threads: 2, password: pass.data(using: .utf8)!, salt: salt!, desiredLength: 32, variant: .id, version: .v13)
        let secretKey = [UInt8](rawHash)

        // Encrypt
        let ivBytes = [UInt8](iv! as Data)
        let textBytes = [UInt8](text as Data)
        let aes = try! AES(key: secretKey, blockMode: CBC(iv: ivBytes), padding: .pkcs5)
        let encrypted = try! aes.encrypt(textBytes)

        // Combine IV and encrypted part.
        let encryptedIVAndTextData = Data(count: ivSize + encrypted.count)
        var encryptedIVAndText = [UInt8](encryptedIVAndTextData as Data)
        encryptedIVAndText[0...ivSize-1] = ivBytes[0...ivSize-1]
        encryptedIVAndText[ivSize...(ivSize + encrypted.count - 1)] = encrypted[0...encrypted.count - 1]

        let map: [String: String?] = ["salt": salt?.base64EncodedString(), "cipher": Data(encryptedIVAndText).base64EncodedString()]
        return map

    }

    public func pbDecrypt(encryptedIvText: String, salt: String, pass: String) -> Data {
        // Extract IV.
        let ivSize = 16
        let encyptedIvTextData = Data(base64Encoded: encryptedIvText)
        let encyptedIvTextBytes = [UInt8](encyptedIvTextData! as Data)
        let ivData = Data(count: ivSize)
        var ivBytes = [UInt8](ivData as Data)
        ivBytes[0...ivSize-1] = encyptedIvTextBytes[0...ivSize-1]


        // Extract encrypted part.
        let encryptedSize = encyptedIvTextBytes.count - ivSize
        let encyptedData = Data(count: encryptedSize)
        var encryptedBytes = [UInt8](encyptedData as Data)
        encryptedBytes[0...encryptedSize-1] = encyptedIvTextBytes[ivSize...encyptedIvTextBytes.count - 1]


        // Hash key.
//    let secretKey = pbkdf2Derivation(password: pass.data(using: .utf8)!, salt: Data(base64Encoded: salt)!, iterations: 10000, outputLength: 32)
//    let (rawHash, _) = try! Argon2.hash(iterations: 1, memoryInKiB: 1 * 1024, threads: 2, password: pass.data(using: .utf8)!, salt: Data(base64Encoded: salt)!, desiredLength: 32, variant: .id, version: .v13)
        let (rawHash, _) = try! Argon2.hash(iterations: 3, memoryInKiB: 4 * 1024, threads: 2, password: pass.data(using: .utf8)!, salt: Data(base64Encoded: salt)!, desiredLength: 32, variant: .id, version: .v13)
        let secretKey = [UInt8](rawHash)


        // Decrypt.
        let aes = try! AES(key: secretKey, blockMode: CBC(iv: ivBytes), padding: .pkcs5)
        let decryptedBytes = try! aes.decrypt(encryptedBytes)

        return Data(decryptedBytes)
    }

    public func cacheUri(uriId: String, uri: String) {
        let connection = db!.newConnection()
        connection.readWrite { (transaction) in
            transaction.setObject(uri, forKey: uriId, inCollection: "SPImages")
        }
    }

    public func getUri(uriId: String) -> String {
        let connection = db!.newConnection()
        var uri: String?
        connection.read { (transaction) in
            uri = transaction.object(forKey: uriId, inCollection: "SPImages") as? String
        }
        return uri!
    }

    public func isInitialized() -> Bool {
        let databaseConnection = db!.newConnection()
        var count = 0
        databaseConnection.readWrite { (transaction) in
            count = transaction.allCollections().count
        }
        if (count == 0) {
            return false
        } else {
            return true
        }
    }
}

extension String {
    subscript(_ i: Int) -> String {
        let idx1 = index(startIndex, offsetBy: i)
        let idx2 = index(idx1, offsetBy: 1)
        return String(self[idx1..<idx2])
    }

    subscript (r: Range<Int>) -> String {
        let start = index(startIndex, offsetBy: r.lowerBound)
        let end = index(startIndex, offsetBy: r.upperBound)
        return String(self[start ..< end])
    }

    subscript (r: CountableClosedRange<Int>) -> String {
        let startIndex = self.index(self.startIndex, offsetBy: r.lowerBound)
        let endIndex = self.index(startIndex, offsetBy: r.upperBound - r.lowerBound)
        return String(self[startIndex...endIndex])
    }
}

extension Date {
    var timestamp: Int64 {
        return Int64((self.timeIntervalSince1970).rounded())
    }

}
