/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *  
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.store;

import android.content.Context;
import android.util.Log;

import com.stiiick.stickprotocol.util.IdentityKeyUtil;
import com.stiiick.stickprotocol.util.Preferences;
import com.stiiick.stickprotocol.recipient.Recipient;
import com.stiiick.stickprotocol.recipient.RecipientId;
import com.stiiick.stickprotocol.util.SessionUtil;
import com.stiiick.stickprotocol.database.IdentityDatabase;
import com.stiiick.stickprotocol.database.IdentityDatabase.VerifiedStatus;
import com.stiiick.stickprotocol.database.DatabaseFactory;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.util.guava.Optional;

import java.util.concurrent.TimeUnit;

public class MyIdentityKeyStore implements IdentityKeyStore {

    private static final int TIMESTAMP_THRESHOLD_SECONDS = 5;


    private static final Object LOCK = new Object();
    private final Context context;

    public MyIdentityKeyStore(Context context) {
        this.context = context;
    }




    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        return IdentityKeyUtil.getIdentityKeyPair(context);
    }


    @Override
    public IdentityKey getIdentity(SignalProtocolAddress address) {
        if (DatabaseFactory.getRecipientDatabase(context).containsPhoneOrUuid(address.getName())) {
            RecipientId recipientId = Recipient.external(context, address.getName()).getId();
            Optional<IdentityDatabase.IdentityRecord> record      = DatabaseFactory.getIdentityDatabase(context).getIdentity(recipientId);

            if (record.isPresent()) {
                return record.get().getIdentityKey();
            } else {
                return null;
            }
        } else {
            Log.w("TRIED", "Tried to get identity for " + address.getName() + ", but no matching recipient existed!");
            return null;
        }
    }

    @Override
    public int getLocalRegistrationId() {
        return Preferences.getLocalRegistrationId(context);
    }


    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey, boolean nonBlockingApproval) {
        synchronized (LOCK) {
            IdentityDatabase         identityDatabase = DatabaseFactory.getIdentityDatabase(context);
            Recipient                recipient        = Recipient.external(context, address.getName());
            Optional<IdentityDatabase.IdentityRecord> identityRecord   = identityDatabase.getIdentity(recipient.getId());

            if (!identityRecord.isPresent()) {
                Log.d("NEW", "Saving new identity...");
                identityDatabase.saveIdentity(recipient.getId(), identityKey, VerifiedStatus.DEFAULT, true, System.currentTimeMillis(), nonBlockingApproval);
                return false;
            } else {
                return true;
            }

//            if (!identityRecord.get().getIdentityKey().equals(identityKey)) {
//                Log.d("REPLACING", "Replacing existing identity...");
//                VerifiedStatus verifiedStatus;
//
//                if (identityRecord.get().getVerifiedStatus() == VerifiedStatus.VERIFIED ||
//                        identityRecord.get().getVerifiedStatus() == VerifiedStatus.UNVERIFIED)
//                {
//                    verifiedStatus = VerifiedStatus.UNVERIFIED;
//                } else {
//                    verifiedStatus = VerifiedStatus.DEFAULT;
//                }
//
//                identityDatabase.saveIdentity(recipient.getId(), identityKey, verifiedStatus, false, System.currentTimeMillis(), nonBlockingApproval);
//                Log.d("ARHIVINGGG", "ARHIVIING");
//                SessionUtil.archiveSiblingSessions(context, address);
//                return true;
//            }

//            if (isNonBlockingApprovalRequired(identityRecord.get())) {
//                Log.i("SETTING", "Setting approval status...");
//                identityDatabase.setApproval(recipient.getId(), nonBlockingApproval);
//                return false;
//            }

//            return false;
        }
    }

    @Override
    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        return saveIdentity(address, identityKey, false);
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        return true;
    }

    private boolean isNonBlockingApprovalRequired(IdentityDatabase.IdentityRecord identityRecord) {
        return !identityRecord.isFirstUse() &&
                System.currentTimeMillis() - identityRecord.getTimestamp() < TimeUnit.SECONDS.toMillis(TIMESTAMP_THRESHOLD_SECONDS) &&
                !identityRecord.isApprovedNonBlocking();
    }

}
