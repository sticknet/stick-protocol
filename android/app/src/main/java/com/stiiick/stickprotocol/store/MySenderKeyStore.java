/*
 *  Copyright (c) 2018-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.store;

import android.content.Context;

import androidx.annotation.NonNull;

import com.stiiick.stickprotocol.database.DatabaseFactory;

import org.whispersystems.libsignal.groups.SenderKeyName;
import org.whispersystems.libsignal.groups.state.SenderKeyRecord;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;

public class MySenderKeyStore implements SenderKeyStore {

    private static final Object FILE_LOCK = new Object();

    @NonNull
    private final Context context;

    public MySenderKeyStore(@NonNull Context context) {
        this.context = context;
    }

    @Override
    public void storeSenderKey(SenderKeyName senderKeyName, SenderKeyRecord record) {
        synchronized (FILE_LOCK) {
            DatabaseFactory.getSenderKeyDatabse(context).insertSenderKey(senderKeyName.hashCode(), record);
        }
    }

    @Override
    public SenderKeyRecord loadSenderKey(SenderKeyName senderKeyName) {
        synchronized (FILE_LOCK) {
            SenderKeyRecord senderKeyRecord = DatabaseFactory.getSenderKeyDatabse(context).getSenderKey(senderKeyName.hashCode());
            if (senderKeyRecord == null)
                senderKeyRecord = new SenderKeyRecord();
            return senderKeyRecord;
        }
    }

}
