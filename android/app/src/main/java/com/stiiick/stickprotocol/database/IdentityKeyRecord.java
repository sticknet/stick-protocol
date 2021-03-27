/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.database;

/**
 * @author Omar Basem
 */

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import static org.whispersystems.libsignal.state.StorageProtos.SignedPreKeyRecordStructure;


public class IdentityKeyRecord {

    int id;
    long timestamp;
    ECKeyPair keyPair;

    public IdentityKeyRecord(int id, long timestamp, ECKeyPair keyPair) {
        this.id = id;
        this.timestamp = timestamp;
        this.keyPair = keyPair;
    }

    public int getId() {
        return this.id;
    }

    public long getTimestamp() {
        return this.timestamp;
    }

    public ECKeyPair getKeyPair() {
        try {
            ECPublicKey publicKey = Curve.decodePoint(this.keyPair.getPublicKey().serialize(), 0);
            ECPrivateKey privateKey = Curve.decodePrivatePoint(this.keyPair.getPrivateKey().serialize());

            return new ECKeyPair(publicKey, privateKey);
        } catch (InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }
}
