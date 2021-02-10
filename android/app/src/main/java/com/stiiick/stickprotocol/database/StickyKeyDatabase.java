/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 *
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

public class StickyKeyDatabase extends Database {


    public static final String TABLE_NAME = "sticky_keys";
    private static final String ID = "_id";
    public static final String STICK_ID = "stick_id";
    public static final String KEY = "key";

    public static final String CREATE_TABLE = "CREATE TABLE " + TABLE_NAME +
            " (" + ID + " INTEGER PRIMARY KEY, " +
            STICK_ID + " INTEGER UNIQUE, " +
            KEY + " TEXT NOT NULL);";
    public static final String DROP_TABLE = "DROP TABLE " + TABLE_NAME + ";";

    StickyKeyDatabase(Context context, SQLCipherOpenHelper databaseHelper) {
        super(context, databaseHelper);
    }

    public @Nullable
    String getStickyKey(String stickId) {
        SQLiteDatabase database = databaseHelper.fetchReadableDatabase();
        try (Cursor cursor = database.query(TABLE_NAME, null, STICK_ID + " = ?",
                new String[]{stickId},
                null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                return cursor.getString(cursor.getColumnIndexOrThrow(KEY));
            }
        }
        return null;
    }

    public void insertStickyKey(String stickId, String key) {
        SQLiteDatabase database = databaseHelper.fetchWritableDatabase();

        ContentValues contentValues = new ContentValues();
        contentValues.put(STICK_ID, stickId);
        contentValues.put(KEY, key);
        database.replace(TABLE_NAME, null, contentValues);
    }

}
