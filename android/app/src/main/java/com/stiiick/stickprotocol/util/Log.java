/*
 *  Copyright © 2018-2022 Sticknet.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.util;



public class Log {



    public static void d(String tag, String message) {
        d(tag, message, null);
    }

    public static void i(String tag, String message) {
        i(tag, message, null);
    }

    public static void e(String tag, String message) {
        e(tag, message, null);
    }

    public static void i(String tag, Throwable t) {
        i(tag, null, t);
    }

    public static void e(String tag, Throwable t) {
        e(tag, null, t);
    }

    public static void d(String tag, String message, Throwable t) {
        android.util.Log.d(tag, message, t);
    }

    public static void i(String tag, String message, Throwable t) {
        android.util.Log.i(tag, message, t);
    }

    public static void e(String tag, String message, Throwable t) {
        android.util.Log.e(tag, message, t);
    }

}
