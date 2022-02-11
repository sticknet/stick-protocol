/*
 *  Copyright © 2018-2022 Stick.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.cipherstream;

import java.io.InputStream;

public abstract class CipherFile {


    public static Builder newStreamBuilder() {
        return new Builder();
    }

    public static class Builder {

        private InputStream       inputStream;
        private long              length;

        private Builder() {}

        public Builder withStream(InputStream inputStream) {
            this.inputStream = inputStream;
            return this;
        }


        public Builder withLength(long length) {
            this.length = length;
            return this;
        }


        public CipherFileStream build() {
            if (inputStream == null) throw new IllegalArgumentException("Must specify stream!");
            if (length == 0)         throw new IllegalArgumentException("No length specified!");

            return new CipherFileStream(inputStream, length);
        }
    }
}
