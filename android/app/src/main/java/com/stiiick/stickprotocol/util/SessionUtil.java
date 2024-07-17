/*
 *  Copyright © 2018-2022 Sticknet.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.util;

import android.content.Context;

import com.stiiick.stickprotocol.store.MySessionStore;

import org.whispersystems.libsignal.SignalProtocolAddress;

public class SessionUtil {

    public static void archiveSiblingSessions(Context context, SignalProtocolAddress address) {
        MySessionStore sessionStore = new MySessionStore(context);
        sessionStore.archiveSiblingSessions(address);
    }
}
