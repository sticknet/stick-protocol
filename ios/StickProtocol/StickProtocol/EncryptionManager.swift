//
//  EncryptionManager.swift
//  STiiiCK
//
//  Created by Omar Basem on 09/08/2020.
//  Copyright © 2020 STiiiCK. All rights reserved.
//

import UIKit

public enum SPEncryptionError: Error {
  case unableToCreateSignalContext
}

/* Performs any Signal operations: creating bundle, decryption, encryption. Use one EncryptionManager per account **/
open class EncryptionManager {

  let storage: StorageManager
  var signalContext: SignalContext

  //In OMEMO world the registration ID is used as the device id and all devices have registration ID of 0.
  open var registrationId: UInt32 {
    get {
      return self.storage.getLocalRegistrationId()
    }
  }


  open var identityKeyPair: IdentityKeyPair {
    get {
      return self.storage.getIdentityKeyPair()
    }
  }

  init(accountKey: String, databaseConnection: YapDatabaseConnection) throws {
    self.storage = StorageManager(accountKey: accountKey, databaseConnection: databaseConnection, delegate: nil)
    let signalStorage = SignalStorage(signalStore: self.storage)
    guard let context = SignalContext(storage: signalStorage) else {
      throw SPEncryptionError.unableToCreateSignalContext
    }
    self.signalContext = context
    self.storage.delegate = self
  }
}

extension EncryptionManager {
  internal func keyHelper() -> KeyHelper? {
    return KeyHelper(context: self.signalContext)
  }

  public func generateSignedPreKey() -> SignedPreKey? {
    let preKeyId = self.keyHelper()?.generateRegistrationId()
    guard let signedPreKey = self.keyHelper()?.generateSignedPreKey(withIdentity: self.identityKeyPair, signedPreKeyId: preKeyId!),
      let data = signedPreKey.serializedData() else {
        return nil
    }
    if self.storage.storeSignedPreKey(data, signedPreKeyId: signedPreKey.preKeyId) {
      return signedPreKey
    }
    return nil
  }


  public func encryptToAddress(_ data: Data, name: String, deviceId: UInt32) throws -> SignalCiphertext {
    let address = SignalAddress(name: name.lowercased(), deviceId: Int32(deviceId))
    let sessionCipher = SessionCipher(address: address, context: self.signalContext)
    return try sessionCipher.encryptData(data)
  }

  public func decryptFromAddress(_ data: Data, name: String, deviceId: UInt32) throws -> Data {
    let address = SignalAddress(name: name.lowercased(), deviceId: Int32(deviceId))
    let sessionCipher = SessionCipher(address: address, context: self.signalContext)
    let cipherText = SignalCiphertext(data: data, type: .unknown)
    return try sessionCipher.decryptCiphertext(cipherText)
  }


  public func generatePreKeys(_ start: UInt, count: UInt) -> [PreKey]? {
    guard let preKeys = self.keyHelper()?.generatePreKeys(withStartingPreKeyId: start, count: count) else {
      return nil
    }
    if self.storage.storePreKeys(preKeys) {
      return preKeys
    }
    return nil
  }
}

extension EncryptionManager: StorageManagerDelegate {

  public func generateNewIdenityKeyPairForAccountKey(_ accountKey: String) -> SPIdentity {
    let keyHelper = self.keyHelper()!
    let keyPair = keyHelper.generateIdentityKeyPair()!
    let registrationId = keyHelper.generateRegistrationId()
    return SPIdentity(accountKey: accountKey, identityKeyPair: keyPair, registrationId: UInt32(registrationId))!
  }

  public func saveIdenityKeyPairForAccountKey(_ accountKey: String, keyPair: IdentityKeyPair, regId registrationId: UInt32) -> SPIdentity {
    return SPIdentity(accountKey: accountKey, identityKeyPair: keyPair, registrationId: registrationId)!
  }
}
