/*
 *  Copyright © 2018-2022 StickNet.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.util;


import androidx.annotation.NonNull;

import java.io.IOException;

public final class Base64 {

    private Base64() {
    }

    public static @NonNull byte[] decode(@NonNull String s) throws IOException {
        return com.stiiick.encoding.Base64.decode(s);
    }

    public static @NonNull String encodeBytes(@NonNull byte[] source) {
        return com.stiiick.encoding.Base64.encodeBytes(source);
    }

    public static @NonNull byte[] decodeOrThrow(@NonNull String s) {
        try {
            return com.stiiick.encoding.Base64.decode(s);
        } catch (IOException e) {
            throw new AssertionError();
        }
    }
}
