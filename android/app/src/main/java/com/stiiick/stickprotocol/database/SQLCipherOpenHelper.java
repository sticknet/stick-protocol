/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.database;


import android.content.Context;

import net.sqlcipher.database.SQLiteDatabase;
import net.sqlcipher.database.SQLiteOpenHelper;
import androidx.annotation.NonNull;

public class SQLCipherOpenHelper extends SQLiteOpenHelper {

    private static final int    DATABASE_VERSION = 1;
    private static final String DATABASE_NAME    = "stick_protocol.db";

    private final DatabaseSecret databaseSecret;

    public SQLCipherOpenHelper(@NonNull Context context, @NonNull DatabaseSecret databaseSecret) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);

        Context context1 = context.getApplicationContext();
        this.databaseSecret = databaseSecret;
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL(IdentityDatabase.CREATE_TABLE);
        db.execSQL(OneTimePreKeyDatabase.CREATE_TABLE);
        db.execSQL(SignedPreKeyDatabase.CREATE_TABLE);
        db.execSQL(IdentityKeyDatabase.CREATE_TABLE);
        db.execSQL(SessionDatabase.CREATE_TABLE);
        db.execSQL(RecipientDatabase.CREATE_TABLE);
        db.execSQL(SenderKeyDatabase.CREATE_TABLE);
        db.execSQL(StickyKeyDatabase.CREATE_TABLE);

    }


    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL(IdentityDatabase.DROP_TABLE);
        db.execSQL(OneTimePreKeyDatabase.DROP_TABLE);
        db.execSQL(SignedPreKeyDatabase.DROP_TABLE);
        db.execSQL(IdentityKeyDatabase.DROP_TABLE);
        db.execSQL(SessionDatabase.DROP_TABLE);
        db.execSQL(RecipientDatabase.DROP_TABLE);
        db.execSQL(SenderKeyDatabase.DROP_TABLE);
        db.execSQL(StickyKeyDatabase.DROP_TABLE);

        db.execSQL(IdentityDatabase.CREATE_TABLE);
        db.execSQL(OneTimePreKeyDatabase.CREATE_TABLE);
        db.execSQL(SignedPreKeyDatabase.CREATE_TABLE);
        db.execSQL(IdentityKeyDatabase.CREATE_TABLE);
        db.execSQL(SessionDatabase.CREATE_TABLE);
        db.execSQL(RecipientDatabase.CREATE_TABLE);
        db.execSQL(SenderKeyDatabase.CREATE_TABLE);
        db.execSQL(StickyKeyDatabase.CREATE_TABLE);
    }

    public SQLiteDatabase fetchReadableDatabase() {
        return getReadableDatabase(databaseSecret.asString());
    }

    public SQLiteDatabase fetchWritableDatabase() {
        return getWritableDatabase(databaseSecret.asString());
    }

}
