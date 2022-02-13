/*
 *  Copyright © 2018-2022 StickNet.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.util;


import android.content.Context;

import com.stiiick.stickprotocol.store.MyPreKeyStore;

import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyStore;
import org.whispersystems.libsignal.util.Medium;

import java.util.LinkedList;
import java.util.List;

public class PreKeyUtil {


    public synchronized static List<PreKeyRecord> generatePreKeys(Context context, int nextPreKeyId, int batchSize) {
        PreKeyStore        preKeyStore    = new MyPreKeyStore(context);
        List<PreKeyRecord> records        = new LinkedList<>();
        int preKeyId = nextPreKeyId;
        for (int i=0;i<batchSize;i++) {
            ECKeyPair    keyPair  = Curve.generateKeyPair();
            PreKeyRecord record   = new PreKeyRecord(preKeyId, keyPair);

            preKeyStore.storePreKey(preKeyId, record);
            records.add(record);
            preKeyId += 1;
        }
        Preferences.setNextPreKeyId(context, preKeyId + 1);
        return records;
    }

    public synchronized static SignedPreKeyRecord generateSignedPreKey(Context context, IdentityKeyPair identityKeyPair, boolean active) {
        try {
            SignedPreKeyStore  signedPreKeyStore = new MyPreKeyStore(context);
            int                signedPreKeyId    = Preferences.getNextSignedPreKeyId(context);
            ECKeyPair          keyPair           = Curve.generateKeyPair();
            byte[]             signature         = Curve.calculateSignature(identityKeyPair.getPrivateKey(), keyPair.getPublicKey().serialize());
            SignedPreKeyRecord record            = new SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), keyPair, signature);

            signedPreKeyStore.storeSignedPreKey(signedPreKeyId, record);
            Preferences.setNextSignedPreKeyId(context, signedPreKeyId + 1);


            if (active) {
                Preferences.setActiveSignedPreKeyId(context, signedPreKeyId);
                Preferences.setActiveSignedPreKeyTimestamp(context, System.currentTimeMillis());
            }
            return record;
        } catch (InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }
}
