/*
 *  Copyright (c) 2018-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.util;


public class NoExternalStorageException extends Exception {

    public NoExternalStorageException() {
    }

    public NoExternalStorageException(String detailMessage) {
        super(detailMessage);
    }
}
