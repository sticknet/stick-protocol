/*
 *  Copyright © 2018-2022 StickNet.
 *  
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.store;

import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;

import com.stiiick.stickprotocol.recipient.Recipient;
import com.stiiick.stickprotocol.recipient.RecipientId;
import com.stiiick.stickprotocol.database.DatabaseFactory;
import com.stiiick.stickprotocol.database.SessionDatabase;

import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionStore;

import java.util.Collections;
import java.util.List;

public class MySessionStore implements SessionStore {

    private static final String TAG = MySessionStore.class.getSimpleName();

    private static final Object FILE_LOCK = new Object();

    @NonNull  private final Context context;

    public MySessionStore(@NonNull Context context) {
        this.context = context;
    }

    @Override
    public SessionRecord loadSession(@NonNull SignalProtocolAddress address) {
        synchronized (FILE_LOCK) {
            RecipientId recipientId   = Recipient.external(context, address.getName()).getId();
            SessionRecord sessionRecord = DatabaseFactory.getSessionDatabase(context).load(recipientId, address.getDeviceId());

            if (sessionRecord == null) {

                return new SessionRecord();
            }

            return sessionRecord;
        }
    }

    @Override
    public void storeSession(@NonNull SignalProtocolAddress address, @NonNull SessionRecord record) {
        synchronized (FILE_LOCK) {
            RecipientId id = Recipient.external(context, address.getName()).getId();
            DatabaseFactory.getSessionDatabase(context).store(id, address.getDeviceId(), record);
        }
    }

    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        synchronized (FILE_LOCK) {
            if (DatabaseFactory.getRecipientDatabase(context).containsPhoneOrUuid(address.getName())) {
                RecipientId   recipientId   = Recipient.external(context, address.getName()).getId();
                SessionRecord sessionRecord = DatabaseFactory.getSessionDatabase(context).load(recipientId, address.getDeviceId());
                return sessionRecord != null &&
                        sessionRecord.getSessionState().hasSenderChain() &&
                        sessionRecord.getSessionState().getSessionVersion() == CiphertextMessage.CURRENT_VERSION;
            } else {
                return false;
            }
        }
    }

    @Override
    public void deleteSession(SignalProtocolAddress address) {
        synchronized (FILE_LOCK) {
            if (DatabaseFactory.getRecipientDatabase(context).containsPhoneOrUuid(address.getName())) {
                RecipientId recipientId = Recipient.external(context, address.getName()).getId();
                DatabaseFactory.getSessionDatabase(context).delete(recipientId, address.getDeviceId());
            }
        }
    }

    @Override
    public void deleteAllSessions(String name) {
        synchronized (FILE_LOCK) {
            if (DatabaseFactory.getRecipientDatabase(context).containsPhoneOrUuid(name)) {
                RecipientId recipientId = Recipient.external(context, name).getId();
                DatabaseFactory.getSessionDatabase(context).deleteAllFor(recipientId);
            }
        }
    }

    @Override
    public List<Integer> getSubDeviceSessions(String name) {
        synchronized (FILE_LOCK) {
            if (DatabaseFactory.getRecipientDatabase(context).containsPhoneOrUuid(name)) {
                RecipientId recipientId = Recipient.external(context, name).getId();
                return DatabaseFactory.getSessionDatabase(context).getSubDevices(recipientId);
            } else {
                return Collections.emptyList();
            }
        }
    }

    public void archiveSiblingSessions(@NonNull SignalProtocolAddress address) {
        synchronized (FILE_LOCK) {
            if (DatabaseFactory.getRecipientDatabase(context).containsPhoneOrUuid(address.getName())) {
                RecipientId                      recipientId = Recipient.external(context, address.getName()).getId();
                List<SessionDatabase.SessionRow> sessions    = DatabaseFactory.getSessionDatabase(context).getAllFor(recipientId);

                for (SessionDatabase.SessionRow row : sessions) {
                    if (row.getDeviceId() != address.getDeviceId()) {
                        row.getRecord().archiveCurrentState();
                        storeSession(new SignalProtocolAddress(Recipient.resolved(row.getRecipientId()).requireServiceId(), row.getDeviceId()), row.getRecord());
                    }
                }
            } else {
                Log.w(TAG, "Tried to archive sibling sessions for " + address.toString() + ", but none existed!");
            }
        }
    }

    public void archiveAllSessions() {
        synchronized (FILE_LOCK) {
            List<SessionDatabase.SessionRow> sessions = DatabaseFactory.getSessionDatabase(context).getAll();

            for (SessionDatabase.SessionRow row : sessions) {
                row.getRecord().archiveCurrentState();
                storeSession(new SignalProtocolAddress(Recipient.resolved(row.getRecipientId()).requireServiceId(), row.getDeviceId()), row.getRecord());
            }
        }
    }
}
