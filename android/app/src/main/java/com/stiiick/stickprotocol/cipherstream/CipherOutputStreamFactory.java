/*
 *  Copyright (c) 2018-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.cipherstream;


import java.io.IOException;
import java.io.OutputStream;

public class CipherOutputStreamFactory implements OutputStreamFactory {

    private final byte[] key;
    private final byte[] iv;

    public CipherOutputStreamFactory(byte[] key, byte[] iv) {
        this.key = key;
        this.iv  = iv;
    }

    @Override
    public DigestingOutputStream createFor(OutputStream wrap) throws IOException {
        return new CipherOutputStream(key, iv, wrap);
    }

}
