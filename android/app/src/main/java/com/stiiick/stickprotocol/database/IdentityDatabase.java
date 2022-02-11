/*
 *  Copyright © 2018-2022 Stick.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.database;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import net.sqlcipher.database.SQLiteDatabase;

import androidx.annotation.NonNull;

import com.stiiick.stickprotocol.util.Base64;
import com.stiiick.stickprotocol.recipient.RecipientId;

import org.greenrobot.eventbus.EventBus;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.guava.Optional;

import java.io.IOException;

public class IdentityDatabase extends Database {

    static final String TABLE_NAME           = "identities";
    private static final String ID                   = "_id";
    static final String RECIPIENT_ID         = "address";
    static final String IDENTITY_KEY         = "key";
    private static final String TIMESTAMP            = "timestamp";
    private static final String FIRST_USE            = "first_use";
    private static final String NONBLOCKING_APPROVAL = "nonblocking_approval";
    static final String VERIFIED             = "verified";

    public static final String CREATE_TABLE = "CREATE TABLE " + TABLE_NAME +
            " (" + ID + " INTEGER PRIMARY KEY, " +
            RECIPIENT_ID + " INTEGER UNIQUE, " +
            IDENTITY_KEY + " TEXT, " +
            FIRST_USE + " INTEGER DEFAULT 0, " +
            TIMESTAMP + " INTEGER DEFAULT 0, " +
            VERIFIED + " INTEGER DEFAULT 0, " +
            NONBLOCKING_APPROVAL + " INTEGER DEFAULT 0);";

    public static final String DROP_TABLE = "DROP TABLE " + TABLE_NAME + ";";

    public enum VerifiedStatus {
        DEFAULT, VERIFIED, UNVERIFIED;

        public int toInt() {
            if      (this == DEFAULT)    return 0;
            else if (this == VERIFIED)   return 1;
            else if (this == UNVERIFIED) return 2;
            else throw new AssertionError();
        }

        public static VerifiedStatus forState(int state) {
            if      (state == 0) return DEFAULT;
            else if (state == 1) return VERIFIED;
            else if (state == 2) return UNVERIFIED;
            else throw new AssertionError("No such state: " + state);
        }
    }

    IdentityDatabase(Context context, SQLCipherOpenHelper databaseHelper) {
        super(context, databaseHelper);
    }

    public Optional<IdentityRecord> getIdentity(@NonNull RecipientId recipientId) {
        SQLiteDatabase database = databaseHelper.fetchReadableDatabase();

        try (Cursor cursor = database.query(TABLE_NAME, null, RECIPIENT_ID + " = ?",
                new String[]{recipientId.serialize()}, null, null, null)) {

            if (cursor != null && cursor.moveToFirst()) {
                return Optional.of(getIdentityRecord(cursor));
            }
        } catch (InvalidKeyException | IOException e) {
            throw new AssertionError(e);
        }

        return Optional.absent();
    }

    public void saveIdentity(@NonNull RecipientId recipientId, IdentityKey identityKey, VerifiedStatus verifiedStatus,
                             boolean firstUse, long timestamp, boolean nonBlockingApproval)
    {
        saveIdentityInternal(recipientId, identityKey, verifiedStatus, firstUse, timestamp, nonBlockingApproval);
    }

    public void setApproval(@NonNull RecipientId recipientId, boolean nonBlockingApproval) {
        SQLiteDatabase database = databaseHelper.fetchWritableDatabase();

        ContentValues contentValues = new ContentValues(2);
        contentValues.put(NONBLOCKING_APPROVAL, nonBlockingApproval);

        database.update(TABLE_NAME, contentValues, RECIPIENT_ID + " = ?", new String[] {recipientId.serialize()});

    }

    private IdentityRecord getIdentityRecord(@NonNull Cursor cursor) throws IOException, InvalidKeyException {
        long        recipientId         = cursor.getLong(cursor.getColumnIndexOrThrow(RECIPIENT_ID));
        String      serializedIdentity  = cursor.getString(cursor.getColumnIndexOrThrow(IDENTITY_KEY));
        long        timestamp           = cursor.getLong(cursor.getColumnIndexOrThrow(TIMESTAMP));
        int         verifiedStatus      = cursor.getInt(cursor.getColumnIndexOrThrow(VERIFIED));
        boolean     nonblockingApproval = cursor.getInt(cursor.getColumnIndexOrThrow(NONBLOCKING_APPROVAL)) == 1;
        boolean     firstUse            = cursor.getInt(cursor.getColumnIndexOrThrow(FIRST_USE))            == 1;
        IdentityKey identity            = new IdentityKey(Base64.decode(serializedIdentity), 0);

        return new IdentityRecord(RecipientId.from(recipientId), identity, VerifiedStatus.forState(verifiedStatus), firstUse, timestamp, nonblockingApproval);
    }

    private void saveIdentityInternal(@NonNull RecipientId recipientId, IdentityKey identityKey, VerifiedStatus verifiedStatus,
                                      boolean firstUse, long timestamp, boolean nonBlockingApproval)
    {
        SQLiteDatabase database          = databaseHelper.fetchWritableDatabase();
        String         identityKeyString = Base64.encodeBytes(identityKey.serialize());

        ContentValues contentValues = new ContentValues();
        contentValues.put(RECIPIENT_ID, recipientId.serialize());
        contentValues.put(IDENTITY_KEY, identityKeyString);
        contentValues.put(TIMESTAMP, timestamp);
        contentValues.put(VERIFIED, verifiedStatus.toInt());
        contentValues.put(NONBLOCKING_APPROVAL, nonBlockingApproval ? 1 : 0);
        contentValues.put(FIRST_USE, firstUse ? 1 : 0);

        database.replace(TABLE_NAME, null, contentValues);

        EventBus.getDefault().post(new IdentityRecord(recipientId, identityKey, verifiedStatus,
                firstUse, timestamp, nonBlockingApproval));
    }

    public static class IdentityRecord {

        private final RecipientId    recipientId;
        private final IdentityKey    identitykey;
        private final VerifiedStatus verifiedStatus;
        private final boolean        firstUse;
        private final long           timestamp;
        private final boolean        nonblockingApproval;

        private IdentityRecord(@NonNull RecipientId recipientId,
                               IdentityKey identitykey, VerifiedStatus verifiedStatus,
                               boolean firstUse, long timestamp, boolean nonblockingApproval)
        {
            this.recipientId         = recipientId;
            this.identitykey         = identitykey;
            this.verifiedStatus      = verifiedStatus;
            this.firstUse            = firstUse;
            this.timestamp           = timestamp;
            this.nonblockingApproval = nonblockingApproval;
        }

        public IdentityKey getIdentityKey() {
            return identitykey;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public VerifiedStatus getVerifiedStatus() {
            return verifiedStatus;
        }

        public boolean isApprovedNonBlocking() {
            return nonblockingApproval;
        }

        public boolean isFirstUse() {
            return firstUse;
        }

        @Override
        public @NonNull String toString() {
            return "{recipientId: " + recipientId + ", identityKey: " + identitykey + ", verifiedStatus: " + verifiedStatus + ", firstUse: " + firstUse + "}";
        }

    }
}
