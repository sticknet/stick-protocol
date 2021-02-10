/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */
package com.stiiick.stickprotocol.database;

import android.content.Context;

public abstract class Database {

    protected SQLCipherOpenHelper databaseHelper;
    protected final Context             context;

    public Database(Context context, SQLCipherOpenHelper databaseHelper) {
        this.context        = context;
        this.databaseHelper = databaseHelper;
    }

}
