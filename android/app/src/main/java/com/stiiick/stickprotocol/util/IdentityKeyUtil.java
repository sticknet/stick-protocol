/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.util;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;

import androidx.annotation.NonNull;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;

import java.io.IOException;

public class IdentityKeyUtil {

    private static final String IDENTITY_PUBLIC_KEY_PREF                    = "pref_identity_public";
    private static final String IDENTITY_PRIVATE_KEY_PREF                   = "pref_identity_private";


    public static boolean hasIdentityKey(Context context) {
        SharedPreferences preferences = context.getSharedPreferences("StickProtocol-Preferences", 0);
        return
                preferences.contains(IDENTITY_PUBLIC_KEY_PREF) &&
                        preferences.contains(IDENTITY_PRIVATE_KEY_PREF);
    }

    public static @NonNull IdentityKey getIdentityKey(@NonNull Context context) {
        if (!hasIdentityKey(context)) throw new AssertionError("There isn't one!");

        try {
            byte[] publicKeyBytes = Base64.decode(retrieve(context, IDENTITY_PUBLIC_KEY_PREF));
            return new IdentityKey(publicKeyBytes, 0);
        } catch (InvalidKeyException | IOException e) {
            throw new AssertionError(e);
        }
    }

    public static @NonNull IdentityKeyPair getIdentityKeyPair(@NonNull Context context) {
        if (!hasIdentityKey(context)) throw new AssertionError("There isn't one!");

        try {
            IdentityKey  publicKey  = getIdentityKey(context);
            ECPrivateKey privateKey = Curve.decodePrivatePoint(Base64.decode(retrieve(context, IDENTITY_PRIVATE_KEY_PREF)));

            return new IdentityKeyPair(publicKey, privateKey);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    public static void generateIdentityKeys(Context context) {
        ECKeyPair    djbKeyPair     = Curve.generateKeyPair();
        IdentityKey  djbIdentityKey = new IdentityKey(djbKeyPair.getPublicKey());
        ECPrivateKey djbPrivateKey  = djbKeyPair.getPrivateKey();

        save(context, IDENTITY_PUBLIC_KEY_PREF, Base64.encodeBytes(djbIdentityKey.serialize()));
        save(context, IDENTITY_PRIVATE_KEY_PREF, Base64.encodeBytes(djbPrivateKey.serialize()));
    }


    private static String retrieve(Context context, String key) {
        SharedPreferences preferences = context.getSharedPreferences("StickProtocol-Preferences", 0);
        return preferences.getString(key, null);
    }

    public static void save(Context context, String key, String value) {
        SharedPreferences preferences   = context.getSharedPreferences("StickProtocol-Preferences", 0);
        Editor preferencesEditor        = preferences.edit();

        preferencesEditor.putString(key, value);
        if (!preferencesEditor.commit()) throw new AssertionError("failed to save identity key/value to shared preferences");
    }
}
