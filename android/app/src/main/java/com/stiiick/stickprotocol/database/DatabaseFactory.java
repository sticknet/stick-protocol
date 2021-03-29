/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.database;

import android.content.Context;
import android.util.Log;

//import net.sqlcipher.database.SQLiteDatabase;
import net.sqlcipher.database.SQLiteDatabase;

import androidx.annotation.NonNull;


public class DatabaseFactory {

    private static final Object lock = new Object();

    private static DatabaseFactory instance;

    private final SQLCipherOpenHelper databaseHelper;
    private final IdentityDatabase identityDatabase;
    private final OneTimePreKeyDatabase preKeyDatabase;
    private final SignedPreKeyDatabase signedPreKeyDatabase;
    private final IdentityKeyDatabase identityKeyDatabase;
    private final SessionDatabase sessionDatabase;
    private final RecipientDatabase recipientDatabase;
    private final SenderKeyDatabase senderKeyDatabse;
    private final FileDatabase fileDatabase;
    private final StickyKeyDatabase stickyKeyDatabase;



    public static DatabaseFactory getInstance(Context context) {
        synchronized (lock) {
            Log.d("XXX", "CALLING DATABASE FACTORY GET INSTANCE");
            if (instance == null) {
                Log.d("XXX", "INSTANCE == NULL");
                instance = new DatabaseFactory(context.getApplicationContext());
            } else {
                Log.d("XXX", "INSTANCE NOT NULL");
            }
            return instance;
        }
    }

    public static FileDatabase getFileDatabase(Context context) {
        Log.d("XXX", "CALLING GET FILE DATABASE");
        return getInstance(context).fileDatabase;
    }

    public static StickyKeyDatabase getStickyKeyDatabase(Context context) {
        return getInstance(context).stickyKeyDatabase;
    }

    public static IdentityDatabase getIdentityDatabase(Context context) {
        return getInstance(context).identityDatabase;
    }

    public static OneTimePreKeyDatabase getPreKeyDatabase(Context context) {
        return getInstance(context).preKeyDatabase;
    }

    public static SignedPreKeyDatabase getSignedPreKeyDatabase(Context context) {
        return getInstance(context).signedPreKeyDatabase;
    }

    public static IdentityKeyDatabase getIdentityKeyDatabase(Context context) {
        return getInstance(context).identityKeyDatabase;
    }

    public static SessionDatabase getSessionDatabase(Context context) {
        return getInstance(context).sessionDatabase;
    }

    public static RecipientDatabase getRecipientDatabase(Context context) {
        return getInstance(context).recipientDatabase;
    }

    public static SenderKeyDatabase getSenderKeyDatabse(Context context) {
        return getInstance(context).senderKeyDatabse;
    }

    public static SQLiteDatabase getBackupDatabase(Context context) {
        return getInstance(context).databaseHelper.fetchReadableDatabase();
    }

    public void resetDatabase(Context context) {
        SQLiteDatabase db = getInstance(context).databaseHelper.fetchReadableDatabase();
        getInstance(context).databaseHelper.onUpgrade(db, db.getVersion(), db.getVersion() + 1);
    }


    private DatabaseFactory(@NonNull Context context) {
        Log.d("XXX", "CALLING DATABASE FACTORY CONSTRUCTOR");
        SQLiteDatabase.loadLibs(context);
        DatabaseSecret databaseSecret   = new DatabaseSecretProvider(context).getOrCreateDatabaseSecret();
        this.databaseHelper       = new SQLCipherOpenHelper(context, databaseSecret);
        this.identityDatabase     = new IdentityDatabase(context, databaseHelper);
        this.preKeyDatabase       = new OneTimePreKeyDatabase(context, databaseHelper);
        this.signedPreKeyDatabase = new SignedPreKeyDatabase(context, databaseHelper);
        this.identityKeyDatabase = new IdentityKeyDatabase(context, databaseHelper);
        this.sessionDatabase      = new SessionDatabase(context, databaseHelper);
        this.recipientDatabase     = new RecipientDatabase(context, databaseHelper);
        this.senderKeyDatabse      = new SenderKeyDatabase(context, databaseHelper);
        this.fileDatabase = new FileDatabase(context, databaseHelper);
        this.stickyKeyDatabase = new StickyKeyDatabase(context, databaseHelper);
    }
}
