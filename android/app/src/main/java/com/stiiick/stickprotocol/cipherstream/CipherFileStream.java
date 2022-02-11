/*
 *  Copyright © 2018-2022 Stick.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.cipherstream;

import java.io.InputStream;

public class CipherFileStream extends CipherFile {

    private final InputStream       inputStream;
    private final long              length;

    public CipherFileStream(InputStream inputStream, long length)
    {
        this.inputStream       = inputStream;
        this.length            = length;
    }

    public InputStream getInputStream() {
        return inputStream;
    }
    public long getLength() {
        return length;
    }
}
