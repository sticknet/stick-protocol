/*
 *  Copyright (c) 2018-2021 STiiiCK.
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
import androidx.annotation.Nullable;

import com.stiiick.stickprotocol.util.Base64;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public class IdentityKeyDatabase extends Database {

    public static final String TABLE_NAME = "identity_prekeys";

    private static final String ID          = "_id";
    public  static final String KEY_ID      = "key_id";
    public  static final String PUBLIC_KEY  = "public_key";
    public  static final String PRIVATE_KEY = "private_key";
    public  static final String TIMESTAMP   = "timestamp";

    public static final String CREATE_TABLE = "CREATE TABLE " + TABLE_NAME +
            " (" + ID + " INTEGER PRIMARY KEY, " +
            KEY_ID + " INTEGER UNIQUE, " +
            PUBLIC_KEY + " TEXT NOT NULL, " +
            PRIVATE_KEY + " TEXT NOT NULL, " +
            TIMESTAMP + " INTEGER DEFAULT 0);";
    public static final String DROP_TABLE = "DROP TABLE " + TABLE_NAME + ";";

    IdentityKeyDatabase(Context context, SQLCipherOpenHelper databaseHelper) {
        super(context, databaseHelper);
    }

    public @Nullable IdentityKeyRecord getIdentityKey(int keyId) {
        SQLiteDatabase database = databaseHelper.fetchReadableDatabase();

        try (Cursor cursor = database.query(TABLE_NAME, null, KEY_ID + " = ?",
                new String[] {String.valueOf(keyId)},
                null, null, null))
        {
            if (cursor != null && cursor.moveToFirst()) {
                try {
                    ECPublicKey  publicKey  = Curve.decodePoint(Base64.decode(cursor.getString(cursor.getColumnIndexOrThrow(PUBLIC_KEY))), 0);
                    ECPrivateKey privateKey = Curve.decodePrivatePoint(Base64.decode(cursor.getString(cursor.getColumnIndexOrThrow(PRIVATE_KEY))));
                    long         timestamp  = cursor.getLong(cursor.getColumnIndexOrThrow(TIMESTAMP));

                    return new IdentityKeyRecord(keyId, timestamp, new ECKeyPair(publicKey, privateKey));
                } catch (InvalidKeyException | IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return null;
    }

    public @NonNull List<IdentityKeyRecord> getAllIdentityKeys() {
        SQLiteDatabase           database = databaseHelper.fetchReadableDatabase();
        List<IdentityKeyRecord> results  = new LinkedList<>();

        try (Cursor cursor = database.query(TABLE_NAME, null, null, null, null, null, null)) {
            while (cursor != null && cursor.moveToNext()) {
                try {
                    int          keyId      = cursor.getInt(cursor.getColumnIndexOrThrow(KEY_ID));
                    ECPublicKey  publicKey  = Curve.decodePoint(Base64.decode(cursor.getString(cursor.getColumnIndexOrThrow(PUBLIC_KEY))), 0);
                    ECPrivateKey privateKey = Curve.decodePrivatePoint(Base64.decode(cursor.getString(cursor.getColumnIndexOrThrow(PRIVATE_KEY))));
                    long         timestamp  = cursor.getLong(cursor.getColumnIndexOrThrow(TIMESTAMP));

                    results.add(new IdentityKeyRecord(keyId, timestamp, new ECKeyPair(publicKey, privateKey)));
                } catch (InvalidKeyException | IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return results;
    }

    public void insertIdentityKey(int keyId, IdentityKeyRecord record) {
        SQLiteDatabase database = databaseHelper.fetchWritableDatabase();

        ContentValues contentValues = new ContentValues();
        contentValues.put(KEY_ID, keyId);
        contentValues.put(PUBLIC_KEY, Base64.encodeBytes(record.getKeyPair().getPublicKey().serialize()));
        contentValues.put(PRIVATE_KEY, Base64.encodeBytes(record.getKeyPair().getPrivateKey().serialize()));
        contentValues.put(TIMESTAMP, record.getTimestamp());

        database.replace(TABLE_NAME, null, contentValues);
    }


    public void removeIdentityKey(int keyId) {
        SQLiteDatabase database = databaseHelper.fetchWritableDatabase();
        database.delete(TABLE_NAME, KEY_ID + " = ?", new String[] {String.valueOf(keyId)});
    }

}
