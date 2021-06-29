/*
 *  Copyright © 2018-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.util;


import androidx.annotation.NonNull;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;


public class Util {

    public static byte[][] split(byte[] input, int firstLength, int secondLength) {
        byte[][] parts = new byte[2][];

        parts[0] = new byte[firstLength];
        System.arraycopy(input, 0, parts[0], 0, firstLength);

        parts[1] = new byte[secondLength];
        System.arraycopy(input, firstLength, parts[1], 0, secondLength);

        return parts;
    }

    public static byte[] getSecretBytes(int size) {
        return getSecretBytes(new SecureRandom(), size);
    }

    public static byte[] getSecretBytes(@NonNull SecureRandom secureRandom, int size) {
        byte[] secret = new byte[size];
        secureRandom.nextBytes(secret);
        return secret;
    }

    public static int toIntExact(long value) {
        if ((int)value != value) {
            throw new ArithmeticException("integer overflow");
        }
        return (int)value;
    }

    public static long copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[8192];
        int read;
        long total = 0;

        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
            total += read;
        }

        in.close();
        out.close();

        return total;
    }

    public static void readFully(InputStream in, byte[] buffer) throws IOException {
        readFully(in, buffer, buffer.length);
    }

    public static void readFully(InputStream in, byte[] buffer, int len) throws IOException {
        int offset = 0;

        for (;;) {
            int read = in.read(buffer, offset, len - offset);
            if (read == -1) throw new EOFException("Stream ended early");

            if (read + offset < len) offset += read;
            else                		 return;
        }
    }


}
