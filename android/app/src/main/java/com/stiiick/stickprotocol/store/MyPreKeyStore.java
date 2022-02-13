/*
 *  Copyright © 2018-2022 StickNet.
 *  
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.store;

import android.content.Context;

import androidx.annotation.NonNull;

import com.stiiick.stickprotocol.database.DatabaseFactory;

import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyStore;

import java.util.List;

public class MyPreKeyStore implements PreKeyStore, SignedPreKeyStore {

    private static final Object FILE_LOCK = new Object();

    @NonNull
    private final Context context;

    public MyPreKeyStore(@NonNull Context context) {
        this.context = context;
    }

    @Override
    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        synchronized (FILE_LOCK) {
            PreKeyRecord preKeyRecord = DatabaseFactory.getPreKeyDatabase(context).getPreKey(preKeyId);

            if (preKeyRecord == null) throw new InvalidKeyIdException("No such key: " + preKeyId);
            else                      return preKeyRecord;
        }
    }

    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        synchronized (FILE_LOCK) {
            SignedPreKeyRecord signedPreKeyRecord = DatabaseFactory.getSignedPreKeyDatabase(context).getSignedPreKey(signedPreKeyId);

            if (signedPreKeyRecord == null) throw new InvalidKeyIdException("No such signed prekey: " + signedPreKeyId);
            else                            return signedPreKeyRecord;
        }
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        synchronized (FILE_LOCK) {
            return DatabaseFactory.getSignedPreKeyDatabase(context).getAllSignedPreKeys();
        }
    }

    public List<PreKeyRecord> loadPreKeys() {
        synchronized (FILE_LOCK) {
            return DatabaseFactory.getPreKeyDatabase(context).getAllPreKeys();
        }
    }

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        synchronized (FILE_LOCK) {
            DatabaseFactory.getPreKeyDatabase(context).insertPreKey(preKeyId, record);
        }
    }

    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        synchronized (FILE_LOCK) {
            DatabaseFactory.getSignedPreKeyDatabase(context).insertSignedPreKey(signedPreKeyId, record);
        }
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        return DatabaseFactory.getPreKeyDatabase(context).getPreKey(preKeyId) != null;
    }

    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        return DatabaseFactory.getSignedPreKeyDatabase(context).getSignedPreKey(signedPreKeyId) != null;
    }

    @Override
    public void removePreKey(int preKeyId) {}

    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        DatabaseFactory.getSignedPreKeyDatabase(context).removeSignedPreKey(signedPreKeyId);
    }
}