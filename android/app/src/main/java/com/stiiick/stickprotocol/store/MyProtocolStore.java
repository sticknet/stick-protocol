/*
 *  Copyright © 2018-2022 Stick.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.store;


import android.content.Context;

import com.stiiick.stickprotocol.database.IdentityKeyRecord;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionStore;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyStore;

import java.util.List;

public class MyProtocolStore implements SignalProtocolStore {

    private final MyPreKeyStore       preKeyStore;
    private final SignedPreKeyStore signedPreKeyStore;
    private final MyIdentityKeyStore  identityKeyStore;
    private final SessionStore      sessionStore;

    public MyProtocolStore(Context context) {
        this.preKeyStore       = new MyPreKeyStore(context);
        this.signedPreKeyStore = new MyPreKeyStore(context);
        this.identityKeyStore  = new MyIdentityKeyStore(context);
        this.sessionStore      = new MySessionStore(context);
    }

    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        return identityKeyStore.getIdentityKeyPair();
    }

    @Override
    public int getLocalRegistrationId() {
        return identityKeyStore.getLocalRegistrationId();
    }

    @Override
    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        return identityKeyStore.saveIdentity(address, identityKey);
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        return identityKeyStore.isTrustedIdentity(address, identityKey, direction);
    }

    @Override
    public IdentityKey getIdentity(SignalProtocolAddress address) {
        return identityKeyStore.getIdentity(address);
    }

    @Override
    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        return preKeyStore.loadPreKey(preKeyId);
    }

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        preKeyStore.storePreKey(preKeyId, record);
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        return preKeyStore.containsPreKey(preKeyId);
    }

    @Override
    public void removePreKey(int preKeyId) {
        preKeyStore.removePreKey(preKeyId);
    }

    @Override
    public SessionRecord loadSession(SignalProtocolAddress axolotlAddress) {
        return sessionStore.loadSession(axolotlAddress);
    }

    @Override
    public List<Integer> getSubDeviceSessions(String number) {
        return sessionStore.getSubDeviceSessions(number);
    }

    @Override
    public void storeSession(SignalProtocolAddress axolotlAddress, SessionRecord record) {
        sessionStore.storeSession(axolotlAddress, record);
    }

    @Override
    public boolean containsSession(SignalProtocolAddress axolotlAddress) {
        return sessionStore.containsSession(axolotlAddress);
    }

    @Override
    public void deleteSession(SignalProtocolAddress axolotlAddress) {
        sessionStore.deleteSession(axolotlAddress);
    }

    @Override
    public void deleteAllSessions(String number) {
        sessionStore.deleteAllSessions(number);
    }

    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        return signedPreKeyStore.loadSignedPreKey(signedPreKeyId);
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        return signedPreKeyStore.loadSignedPreKeys();
    }

    public List<PreKeyRecord> loadPreKeys() {
        return preKeyStore.loadPreKeys();
    }

    public List<IdentityKeyRecord> loadIdentityKeys() {
        return identityKeyStore.loadIdentityKeys();
    }

    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        signedPreKeyStore.storeSignedPreKey(signedPreKeyId, record);
    }

    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        return signedPreKeyStore.containsSignedPreKey(signedPreKeyId);
    }

    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        signedPreKeyStore.removeSignedPreKey(signedPreKeyId);
    }
}
