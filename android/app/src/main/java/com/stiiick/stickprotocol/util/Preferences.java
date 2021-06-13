/*
 *  Copyright (c) 2018-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.util;


import android.content.Context;
import android.preference.PreferenceManager;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.whispersystems.libsignal.util.Medium;

import java.security.SecureRandom;
import java.util.UUID;

public class Preferences {

    private static final String LOCAL_REGISTRATION_ID_PREF       = "pref_local_registration_id";
    private static final String DATABASE_ENCRYPTED_SECRET     = "pref_database_encrypted_secret";
    private static final String DATABASE_UNENCRYPTED_SECRET   = "pref_database_unencrypted_secret";

    private static final String NEXT_PRE_KEY_ID          = "pref_next_pre_key_id";
    private static final String ACTIVE_SIGNED_PRE_KEY_ID = "pref_active_signed_pre_key_id";
    private static final String ACTIVE_SIGNED_PRE_KEY_TIMESTAMP = "pref_active_signed_pre_key_timestamp";
    private static final String NEXT_SIGNED_PRE_KEY_ID   = "pref_next_signed_pre_key_id";

    private static final String ACTIVE_IDENTITY_KEY_ID = "pref_active_identity_key_id";
    private static final String ACTIVE_IDENTITY_KEY_TIMESTAMP = "pref_active_identity_key_timestamp";
    private static final String NEXT_IDENTITY_KEY_ID   = "pref_next_identity_key_id";

    public static void setDatabaseEncryptedSecret(@NonNull Context context, @NonNull String secret) {
        setStringPreference(context, DATABASE_ENCRYPTED_SECRET, secret);
    }

    public static void setDatabaseUnencryptedSecret(@NonNull Context context, @Nullable String secret) {
        setStringPreference(context, DATABASE_UNENCRYPTED_SECRET, secret);
    }

    public static @Nullable String getDatabaseUnencryptedSecret(@NonNull Context context) {
        return getStringPreference(context, DATABASE_UNENCRYPTED_SECRET, null);
    }

    public static int getLocalRegistrationId(Context context) {
        return getIntegerPreference(context, LOCAL_REGISTRATION_ID_PREF, 0);
    }

    public static void setLocalRegistrationId(Context context, int registrationId) {
        setIntegerPrefrence(context, LOCAL_REGISTRATION_ID_PREF, registrationId);
    }
    private static int getIntegerPreference(Context context, String key, int defaultValue) {
        return PreferenceManager.getDefaultSharedPreferences(context).getInt(key, defaultValue);
    }

    private static long getLongPreference(Context context, String key, long defaultValue) {
        return PreferenceManager.getDefaultSharedPreferences(context).getLong(key, defaultValue);
    }

    public static @Nullable String getDatabaseEncryptedSecret(@NonNull Context context) {
        return getStringPreference(context, DATABASE_ENCRYPTED_SECRET, null);
    }

    public static void setStringPreference(Context context, String key, String value) {
        PreferenceManager.getDefaultSharedPreferences(context).edit().putString(key, value).apply();
    }

    public static String getStringPreference(Context context, String key, String defaultValue) {
        return PreferenceManager.getDefaultSharedPreferences(context).getString(key, defaultValue);
    }

    public static int getNextPreKeyId(@NonNull Context context) {
        return getIntegerPreference(context, NEXT_PRE_KEY_ID, 0);
    }

    public static void setNextPreKeyId(@NonNull Context context, int value) {
        setIntegerPrefrence(context, NEXT_PRE_KEY_ID, value);
    }

    private static void setIntegerPrefrence(Context context, String key, int value) {
        PreferenceManager.getDefaultSharedPreferences(context).edit().putInt(key, value).apply();
    }

    private static void setLongPrefrence(Context context, String key, long value) {
        PreferenceManager.getDefaultSharedPreferences(context).edit().putLong(key, value).apply();
    }

    public static int getNextSignedPreKeyId(@NonNull Context context) {
        return getIntegerPreference(context, NEXT_SIGNED_PRE_KEY_ID, 0);
    }

    public static void setNextSignedPreKeyId(@NonNull Context context, int value) {
        setIntegerPrefrence(context, NEXT_SIGNED_PRE_KEY_ID, value);
    }

    public static int getNextIdentityKeyId(@NonNull Context context) {
        return getIntegerPreference(context, NEXT_IDENTITY_KEY_ID, 0);
    }

    public static void setNextIdentityKeyId(@NonNull Context context, int value) {
        setIntegerPrefrence(context, NEXT_IDENTITY_KEY_ID, value);
    }

    public static int getActiveSignedPreKeyId(@NonNull Context context) {
        return getIntegerPreference(context, ACTIVE_SIGNED_PRE_KEY_ID, -1);
    }

    public static void setActiveSignedPreKeyId(@NonNull Context context, int value) {
        setIntegerPrefrence(context, ACTIVE_SIGNED_PRE_KEY_ID, value);;
    }

    public static long getActiveSignedPreKeyTimestamp(@NonNull Context context) {
        return getLongPreference(context, ACTIVE_SIGNED_PRE_KEY_TIMESTAMP, 0);
    }

    public static void setActiveSignedPreKeyTimestamp(@NonNull Context context, long value) {
        setLongPrefrence(context, ACTIVE_SIGNED_PRE_KEY_TIMESTAMP, value);;
    }

    public static int getActiveIdentityKeyId(@NonNull Context context) {
        return getIntegerPreference(context, ACTIVE_IDENTITY_KEY_ID, -1);
    }

    public static void setActiveIdentityKeyId(@NonNull Context context, int value) {
        setIntegerPrefrence(context, ACTIVE_IDENTITY_KEY_ID, value);;
    }

    public static long getActiveIdentityKeyTimestamp(@NonNull Context context) {
        return getLongPreference(context, ACTIVE_IDENTITY_KEY_TIMESTAMP, 0);
    }

    public static void setActiveIdentityKeyTimestamp(@NonNull Context context, long value) {
        setLongPrefrence(context, ACTIVE_IDENTITY_KEY_TIMESTAMP, value);;
    }

}
