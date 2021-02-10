/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 *
 */

package com.stiiick.stickprotocol.database;

import androidx.annotation.NonNull;

import com.stiiick.stickprotocol.util.Hex;

import java.io.IOException;

public class DatabaseSecret {

    private final byte[] key;
    private final String encoded;

    public DatabaseSecret(@NonNull byte[] key) {
        this.key = key;
        this.encoded = Hex.toStringCondensed(key);
    }

    public DatabaseSecret(@NonNull String encoded) throws IOException {
        this.key     = Hex.fromStringCondensed(encoded);
        this.encoded = encoded;
    }

    public String asString() {
        return encoded;
    }

    public byte[] asBytes() {
        return key;
    }
}
