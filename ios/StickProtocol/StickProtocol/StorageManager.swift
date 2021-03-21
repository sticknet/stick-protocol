//
//  SPStorageManager.swift
//  ChatSecure
//
//  Created by David Chiles on 7/21/16.
//  Copyright © 2016 Chris Ballinger. All rights reserved.
//

import UIKit

public protocol StorageManagerDelegate: class {
    /** Generate a new account key*/
    func generateNewIdenityKeyPairForAccountKey(_ accountKey:String) -> SPIdentity
  func saveIdenityKeyPairForAccountKey(_ accountKey:String, keyPair: IdentityKeyPair, regId: UInt32) -> SPIdentity
}

/**
 * This class implements the SignalStore. One SPStorageManager should be created per account key/collection.
 */
open class StorageManager: NSObject {
    public let accountKey:String
    public let databaseConnection:YapDatabaseConnection
    open weak var delegate:StorageManagerDelegate?
    
    /**
     Create a Store Manager for each account.
     
     - parameter accountKey: The yap key for the parent account.
     - parameter databaseConnection: The yap connection to use internally
     - parameter delegate: An object that handles SPStorageManagerDelegate
     */
    public init(accountKey:String, databaseConnection:YapDatabaseConnection, delegate:StorageManagerDelegate?) {
        self.accountKey = accountKey
        self.databaseConnection = databaseConnection
        self.delegate = delegate
    }
    
    /**
     Convenience function to create a new SPIdentity and save it to yap
     
     - returns: an SPIdentity that is already saved to the database
     */
    fileprivate func generateNewIdenityKeyPair() -> SPIdentity {
        // Might be a better way to guarantee we have an SPIdentity
        let identityKeyPair = (self.delegate?.generateNewIdenityKeyPairForAccountKey(self.accountKey))!
        
        self.databaseConnection.readWrite { (transaction) in
            identityKeyPair.save(with: transaction)
        }
        return identityKeyPair
    }
  
    public func saveIdenityKeyPair(keyPair: IdentityKeyPair, regId: UInt32) -> SPIdentity {
        // Might be a better way to guarantee we have an OTRIdentity
        let identityKeyPair = (self.delegate?.saveIdenityKeyPairForAccountKey(self.accountKey, keyPair: keyPair, regId: regId))!

        self.databaseConnection.readWrite { (transaction) in
            identityKeyPair.save(with: transaction)
        }
        return identityKeyPair
    }
    
    //MARK: Database Utilities
    
    /**
     Fetches the SPIdentity for the account key from this class.
     
     returns: An SPIdentity or nil if none was created and stored.
     */
  
  fileprivate func identity() -> SPIdentity? {
      var identityKeyPair:SPIdentity? = nil
      self.databaseConnection.read { (transaction) in
          identityKeyPair = SPIdentity.fetchObject(withUniqueID: self.accountKey, transaction: transaction)
      }
      
      return identityKeyPair
  }
  
  
    fileprivate func storePreKey(_ preKey: Data, preKeyId: UInt32, transaction:YapDatabaseReadWriteTransaction) -> Bool {
        guard let preKeyDatabaseObject = SPPreKey(accountKey: self.accountKey, keyId: preKeyId, keyData: preKey) else {
            return false
        }
        preKeyDatabaseObject.save(with: transaction)
        return true
    }
    
    /**
     Save a bunch of pre keys in one database transaction
     
     - parameters preKeys: The array of pre-keys to be stored
     
     - return: Whether the storage was successufl
     */
    open func storePreKeys(_ preKeys:[PreKey]) -> Bool {
        
        if preKeys.count == 0 {
            return true
        }
        
        var success = false
        self.databaseConnection.readWrite { (transaction) in
            for pKey in preKeys {
                if let data = pKey.serializedData() {
                    success = self.storePreKey(data, preKeyId: pKey.preKeyId, transaction: transaction)
                } else {
                    success = false
                }
                
                if !success {
                    break
                }
            }
        }
        return success
    }
}

//MARK: SignalStore
extension StorageManager: SignalStore {
  
    //MARK: SessionStore
    public func sessionRecord(for address: SignalAddress) -> Data? {
        let yapKey = SPSignalSession.uniqueKey(forAccountKey: self.accountKey, name: address.name, deviceId: address.deviceId)
        var sessionData:Data? = nil
        self.databaseConnection.read { (transaction) in
            sessionData = SPSignalSession.fetchObject(withUniqueID: yapKey, transaction: transaction)?.sessionData
        }
        return sessionData
    }
    
  public func storeSessionRecord(_ recordData: Data, for address: SignalAddress) -> Bool {
        guard let session = SPSignalSession(accountKey: self.accountKey, name: address.name, deviceId: address.deviceId, sessionData: recordData) else {
            return false
        }
        self.databaseConnection.readWrite { (transaction) in
            session.save(with: transaction)
        }
        return true
    }
    
    public func sessionRecordExists(for address: SignalAddress) -> Bool {
        if let result = self.sessionRecord(for: address) {
            return true
        } else {
            return false
        }
    }
    
    public func deleteSessionRecord(for address: SignalAddress) -> Bool {
        let yapKey = SPSignalSession.uniqueKey(forAccountKey: self.accountKey, name: address.name, deviceId: address.deviceId)
        self.databaseConnection.readWrite { (transaction) in
            transaction.removeObject(forKey: yapKey, inCollection: SPSignalSession.collection)
        }
        return true
    }
    
    public func allDeviceIds(forAddressName addressName: String) -> [NSNumber] {
      return [0]
    }
    
    public func deleteAllSessions(forAddressName addressName: String) -> Int32 {
      return 0
    }
    
    //MARK: PreKeyStore
    public func loadPreKey(withId preKeyId: UInt32) -> Data? {
        var preKeyData:Data? = nil
        self.databaseConnection.read { (transaction) in
            let yapKey = SPPreKey.uniqueKey(forAccountKey: self.accountKey, keyId: preKeyId)
            if let signedPreKey = SPPreKey.fetchObject(withUniqueID: yapKey, transaction: transaction) {
                preKeyData = signedPreKey.keyData
            }
        }
        return preKeyData
    }
    
    public func storePreKey(_ preKey: Data, preKeyId: UInt32) -> Bool {
        var result = false
        self.databaseConnection.readWrite { (transaction) in
            result = self.storePreKey(preKey, preKeyId: preKeyId, transaction: transaction)
        }
        return result
    }
    
    public func containsPreKey(withId preKeyId: UInt32) -> Bool {
        if let _ = self.loadPreKey(withId: preKeyId) {
            return true
        } else {
            return false
        }
    }
    
    /// Returns true if deleted, false if not found
    public func deletePreKey(withId preKeyId: UInt32) -> Bool {
        var result = false
        self.databaseConnection.readWrite { (transaction) in
            let yapKey = SPPreKey.uniqueKey(forAccountKey: self.accountKey, keyId: preKeyId)
            if let preKey = SPPreKey.fetchObject(withUniqueID: yapKey, transaction: transaction) {
                preKey.keyData = nil
                preKey.save(with: transaction)
                result = true
            }
            
        }
        return result
    }
    
  //MARK: SignedPreKeyStore
  public func loadSignedPreKey(withId signedPreKeyId: UInt32) -> Data? {
      var preKeyData:Data? = nil
      self.databaseConnection.read { (transaction) in
          if let signedPreKey = SPSignedPreKey.fetchObject(withUniqueID: self.accountKey, transaction: transaction) {
              preKeyData = signedPreKey.keyData
          }
      }
      
      return preKeyData
  }
    
  public func storeSignedPreKey(_ signedPreKey: Data, signedPreKeyId: UInt32) -> Bool {
      guard let signedPreKeyDatabaseObject = SPSignedPreKey(accountKey: self.accountKey, keyId: signedPreKeyId, keyData: signedPreKey) else {
          return false
      }
      self.databaseConnection.readWrite { (transaction) in
          signedPreKeyDatabaseObject.save(with: transaction)
      }
      return true
      
  }
    
    public func containsSignedPreKey(withId signedPreKeyId: UInt32) -> Bool {
        if let _ = self.loadSignedPreKey(withId: signedPreKeyId) {
            return true
        } else {
            return false
        }
    }
    
    public func removeSignedPreKey(withId signedPreKeyId: UInt32) -> Bool {
        self.databaseConnection.readWrite { (transaction) in
            transaction.removeObject(forKey: self.accountKey, inCollection: SPSignedPreKey.collection)
        }
        return true
    }
    
    //MARK: IdentityKeyStore
    public func getIdentityKeyPair() -> IdentityKeyPair {
        if let result = self.identity() {
            return result.identityKeyPair
        }
        //Generate new identitiy key pair?
        return self.generateNewIdenityKeyPair().identityKeyPair
    }
    
    public func getLocalRegistrationId() -> UInt32 {
        
        if let result = self.identity() {
            return result.registrationId;
        } else {
            //Generate new registration ID?
            return self.generateNewIdenityKeyPair().registrationId
        }
    }
    
    
    public func saveIdentity(_ address: SignalAddress, identityKey: Data?) -> Bool {
        self.databaseConnection.readWrite { (transaction) in
        }
      return true;
    }
    
    
    // We always return true here because we want Signal to always encrypt and decrypt messages. We deal with trust elsewhere.
    public func isTrustedIdentity(_ address: SignalAddress, identityKey: Data) -> Bool {
        return true
    }
    
    //MARK: SenderKeyStore
  fileprivate func storeSenderKey(_ senderKey: Data, senderKeyId: Int32, transaction:YapDatabaseReadWriteTransaction) -> Bool {
      guard let senderKeyDatabaseObject = SPSenderKey(accountKey: self.accountKey, keyId: senderKeyId, keyData: senderKey) else {
          return false
      }
      senderKeyDatabaseObject.save(with: transaction)
      return true
  }
  
  public func storeSenderKey(_ senderKey: Data, senderKeyName: SenderKeyName) -> Bool {
      var result = false
    let senderKeyId = senderKeyName.hashCode()
      self.databaseConnection.readWrite { (transaction) in
          result = self.storeSenderKey(senderKey, senderKeyId: senderKeyId, transaction: transaction)
      }
      return result
  }
  
  public func loadSenderKey(for senderKeyName: SenderKeyName) -> Data? {
     var senderKeyData:Data? = nil
    let senderKeyId = senderKeyName.hashCode()
         self.databaseConnection.read { (transaction) in
             let yapKey = SPSenderKey.uniqueKey(forAccountKey: self.accountKey, keyId: senderKeyId)
             if let senderKey = SPSenderKey.fetchObject(withUniqueID: yapKey, transaction: transaction) {
                 senderKeyData = senderKey.keyData
             } else {
              senderKeyData = Data()
          }
         }
         return senderKeyData
  }
}
