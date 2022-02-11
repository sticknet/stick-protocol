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

import androidx.annotation.Nullable;

import com.stiiick.stickprotocol.util.Base64;

import org.whispersystems.libsignal.groups.state.SenderKeyRecord;

import java.io.IOException;

public class SenderKeyDatabase extends Database {


    public static final String TABLE_NAME = "sender_keys";
    private static final String ID = "_id";
    public static final String KEY_ID = "key_id";
    public static final String KEY = "key";

    public static final String CREATE_TABLE = "CREATE TABLE " + TABLE_NAME +
            " (" + ID + " INTEGER PRIMARY KEY, " +
            KEY_ID + " INTEGER UNIQUE, " +
            KEY + " TEXT NOT NULL);";
    public static final String DROP_TABLE = "DROP TABLE " + TABLE_NAME + ";";

    SenderKeyDatabase(Context context, SQLCipherOpenHelper databaseHelper) {
        super(context, databaseHelper);
    }

    public @Nullable
    SenderKeyRecord getSenderKey(int keyId) {
        SQLiteDatabase database = databaseHelper.fetchReadableDatabase();

        try (Cursor cursor = database.query(TABLE_NAME, null, KEY_ID + " = ?",
                new String[]{String.valueOf(keyId)},
                null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {

                return new SenderKeyRecord(Base64.decode(cursor.getString(cursor.getColumnIndexOrThrow(KEY))));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public void insertSenderKey(int keyId, SenderKeyRecord record) {
        SQLiteDatabase database = databaseHelper.fetchWritableDatabase();

        ContentValues contentValues = new ContentValues();
        contentValues.put(KEY_ID, keyId);
        contentValues.put(KEY, Base64.encodeBytes(record.serialize()));
        database.replace(TABLE_NAME, null, contentValues);
    }
}
