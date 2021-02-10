/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.database;


import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.stiiick.stickprotocol.recipient.RecipientId;
import com.stiiick.stickprotocol.util.Base64;
import com.stiiick.stickprotocol.util.UuidUtil;

import net.sqlcipher.database.SQLiteDatabase;

import org.whispersystems.libsignal.util.guava.Optional;

import java.util.UUID;

public class RecipientDatabase extends Database {

    private static final String TAG = RecipientDatabase.class.getSimpleName();

    static final String TABLE_NAME               = "recipient";
    public  static final String ID                       = "_id";
    private static final String UUID                     = "uuid";
    private static final String GROUP_TYPE               = "group_type";

    private static final String DIRTY                    = "dirty";

    private static final String IDENTITY_STATUS          = "identity_status";
    private static final String IDENTITY_KEY             = "identity_key";


    private static final String[] RECIPIENT_PROJECTION = new String[] {
            UUID, GROUP_TYPE,
           DIRTY
    };

    private static final String[]     ID_PROJECTION              = new String[]{ID};

    public enum DirtyState {
        CLEAN(0), UPDATE(1), INSERT(2), DELETE(3);

        private final int id;

        DirtyState(int id) {
            this.id = id;
        }

        int getId() {
            return id;
        }

        public static DirtyState fromId(int id) {
            return values()[id];
        }
    }

    public enum GroupType {
        NONE(0), MMS(1), SIGNAL_V1(2);

        private final int id;

        GroupType(int id) {
            this.id = id;
        }

        int getId() {
            return id;
        }

        public static GroupType fromId(int id) {
            return values()[id];
        }
    }

    public static final String CREATE_TABLE =
            "CREATE TABLE " + TABLE_NAME + " (" + ID                       + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    UUID                     + " TEXT UNIQUE DEFAULT NULL, " +
                    GROUP_TYPE               + " INTEGER DEFAULT " + GroupType.NONE.getId() +  ", " +
                    DIRTY                    + " INTEGER DEFAULT " + DirtyState.CLEAN.getId() + ");";
    public static final String DROP_TABLE = "DROP TABLE " + TABLE_NAME + ";";



    public RecipientDatabase(Context context, SQLCipherOpenHelper databaseHelper) {
        super(context, databaseHelper);
    }


    public @NonNull boolean containsPhoneOrUuid(@NonNull String id) {
        SQLiteDatabase db    = databaseHelper.fetchReadableDatabase();
        String         query = UUID + " = ? ";
        String[]       args  = new String[]{id};

        try (Cursor cursor = db.query(TABLE_NAME, new String[] { ID }, query, args, null, null, null)) {
            return cursor != null && cursor.moveToFirst();
        }
    }


    public @NonNull Optional<RecipientId> getByUuid(@NonNull UUID uuid) {
        return getByColumn(UUID, uuid.toString());
    }



    private @NonNull GetOrInsertResult getOrInsertByColumn(@NonNull String column, String value) {
        if (TextUtils.isEmpty(value)) {
            throw new AssertionError(column + " cannot be empty.");
        }

        Optional<RecipientId> existing = getByColumn(column, value);

        if (existing.isPresent()) {
            return new GetOrInsertResult(existing.get(), false);
        } else {
            ContentValues values = new ContentValues();
            values.put(column, value);

            long id = databaseHelper.fetchWritableDatabase().insert(TABLE_NAME, null, values);

            if (id < 0) {
                existing = getByColumn(column, value);

                if (existing.isPresent()) {
                    return new GetOrInsertResult(existing.get(), false);
                } else {
                    throw new AssertionError("Failed to insert recipient!");
                }
            } else {
                return new GetOrInsertResult(RecipientId.from(id), true);
            }
        }
    }


    public @NonNull RecipientId getOrInsertFromUuid(@NonNull UUID uuid) {
        return getOrInsertByColumn(UUID, uuid.toString()).recipientId;
    }

    private @NonNull Optional<RecipientId> getByColumn(@NonNull String column, String value) {
        SQLiteDatabase db    = databaseHelper.fetchWritableDatabase();
        String         query = column + " = ?";
        String[]       args  = new String[] { value };

        try (Cursor cursor = db.query(TABLE_NAME, ID_PROJECTION, query, args, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                return Optional.of(RecipientId.from(cursor.getLong(cursor.getColumnIndexOrThrow(ID))));
            } else {
                return Optional.absent();
            }
        }
    }

    private static @NonNull RecipientSettings getRecipientSettings(@NonNull Cursor cursor) {
        long    id                         = cursor.getLong(cursor.getColumnIndexOrThrow(ID));
        UUID    uuid                       = UuidUtil.parseOrNull(cursor.getString(cursor.getColumnIndexOrThrow(UUID)));
        int     groupType                  = cursor.getInt(cursor.getColumnIndexOrThrow(GROUP_TYPE));
        String  identityKeyRaw             = cursor.getString(cursor.getColumnIndexOrThrow(IDENTITY_KEY));
        int     identityStatusRaw          = cursor.getInt(cursor.getColumnIndexOrThrow(IDENTITY_STATUS));
        byte[] identityKey = identityKeyRaw != null ? Base64.decodeOrThrow(identityKeyRaw) : null;
        IdentityDatabase.VerifiedStatus identityStatus = IdentityDatabase.VerifiedStatus.forState(identityStatusRaw);
        return new RecipientSettings(RecipientId.from(id), uuid,  GroupType.fromId(groupType), identityKey, identityStatus);
    }

    public static class RecipientSettings {
        private final RecipientId                     id;
        private final UUID                            uuid;
        private final GroupType                       groupType;
        private final byte[]                          identityKey;
        private final IdentityDatabase.VerifiedStatus identityStatus;

        RecipientSettings(@NonNull RecipientId id,
                          @Nullable UUID uuid,
                          @NonNull GroupType groupType,
                          @Nullable byte[] identityKey,
                          @NonNull IdentityDatabase.VerifiedStatus identityStatus)
        {
            this.id                     = id;
            this.uuid                   = uuid;
            this.groupType              = groupType;
            this.identityKey            = identityKey;
            this.identityStatus         = identityStatus;
        }

        public RecipientId getId() {
            return id;
        }

        public @Nullable UUID getUuid() {
            return uuid;
        }

        public @Nullable byte[] getIdentityKey() {
            return identityKey;
        }

        public @NonNull IdentityDatabase.VerifiedStatus getIdentityStatus() {
            return identityStatus;
        }
    }

    private static class GetOrInsertResult {
        final RecipientId recipientId;
        final boolean     neededInsert;

        private GetOrInsertResult(@NonNull RecipientId recipientId, boolean neededInsert) {
            this.recipientId  = recipientId;
            this.neededInsert = neededInsert;
        }
    }
}
