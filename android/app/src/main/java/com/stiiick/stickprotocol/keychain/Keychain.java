/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.keychain;

import android.content.Context;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringDef;

import com.stiiick.stickprotocol.keychain.PrefsStorage.ResultSet;
import com.stiiick.stickprotocol.keychain.cipherStorage.CipherStorage;
import com.stiiick.stickprotocol.keychain.cipherStorage.CipherStorage.DecryptionResult;
import com.stiiick.stickprotocol.keychain.cipherStorage.CipherStorage.DecryptionResultHandler;
import com.stiiick.stickprotocol.keychain.cipherStorage.CipherStorage.EncryptionResult;
import com.stiiick.stickprotocol.keychain.cipherStorage.CipherStorageBase;
import com.stiiick.stickprotocol.keychain.cipherStorage.CipherStorageKeystoreAesCbc;
import com.stiiick.stickprotocol.keychain.exceptions.CryptoFailedException;
import com.stiiick.stickprotocol.keychain.exceptions.EmptyParameterException;
import com.stiiick.stickprotocol.keychain.exceptions.KeyStoreAccessException;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;

@SuppressWarnings({"unused", "WeakerAccess", "SameParameterValue"})
public class Keychain {
  //region Constants
  public static final String KEYCHAIN_MODULE = "KeychainManager";
  public static final String FINGERPRINT_SUPPORTED_NAME = "Fingerprint";
  public static final String FACE_SUPPORTED_NAME = "Face";
  public static final String IRIS_SUPPORTED_NAME = "Iris";
  public static final String EMPTY_STRING = "";

  private static final String LOG_TAG = Keychain.class.getSimpleName();

  @StringDef({AccessControl.NONE
    , AccessControl.USER_PRESENCE
    , AccessControl.BIOMETRY_ANY
    , AccessControl.BIOMETRY_CURRENT_SET
    , AccessControl.DEVICE_PASSCODE
    , AccessControl.APPLICATION_PASSWORD
    , AccessControl.BIOMETRY_ANY_OR_DEVICE_PASSCODE
    , AccessControl.BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE})
  @interface AccessControl {
    String NONE = "None";
    String USER_PRESENCE = "UserPresence";
    String BIOMETRY_ANY = "BiometryAny";
    String BIOMETRY_CURRENT_SET = "BiometryCurrentSet";
    String DEVICE_PASSCODE = "DevicePasscode";
    String APPLICATION_PASSWORD = "ApplicationPassword";
    String BIOMETRY_ANY_OR_DEVICE_PASSCODE = "BiometryAnyOrDevicePasscode";
    String BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE = "BiometryCurrentSetOrDevicePasscode";
  }

  @interface AuthPromptOptions {
    String TITLE = "title";
    String SUBTITLE = "subtitle";
    String DESCRIPTION = "description";
    String CANCEL = "cancel";
  }

  /** Options mapping keys. */
  @interface Maps {
    String ACCESS_CONTROL = "accessControl";
    String ACCESS_GROUP = "accessGroup";
    String ACCESSIBLE = "accessible";
    String AUTH_PROMPT = "authenticationPrompt";
    String AUTH_TYPE = "authenticationType";
    String SERVICE = "service";
    String SECURITY_LEVEL = "securityLevel";
    String RULES = "rules";

    String USERNAME = "username";
    String PASSWORD = "password";
    String STORAGE = "storage";
  }

  /** Known error codes. */
  @interface Errors {
    String E_EMPTY_PARAMETERS = "E_EMPTY_PARAMETERS";
    String E_CRYPTO_FAILED = "E_CRYPTO_FAILED";
    String E_KEYSTORE_ACCESS_ERROR = "E_KEYSTORE_ACCESS_ERROR";
    String E_SUPPORTED_BIOMETRY_ERROR = "E_SUPPORTED_BIOMETRY_ERROR";
    /** Raised for unexpected errors. */
    String E_UNKNOWN_ERROR = "E_UNKNOWN_ERROR";
  }

  /** Supported ciphers. */
  @StringDef({KnownCiphers.AES})
  public @interface KnownCiphers {
    /** AES encryption. */
    String AES = "KeystoreAESCBC";
  }

  /** Secret manipulation rules. */
  @StringDef({Rules.AUTOMATIC_UPGRADE, Rules.NONE})
  @interface Rules {
    String NONE = "none";
    String AUTOMATIC_UPGRADE = "automaticUpgradeToMoreSecuredStorage";
  }
  //endregion

  //region Members
  /** Name-to-instance lookup  map. */
  private final Map<String, CipherStorage> cipherStorageMap = new HashMap<>();
  /** Shared preferences storage. */
  private final PrefsStorage prefsStorage;
  //endregion

  //region Initialization

  /** Default constructor. */
  public Keychain(@NonNull final Context context) {
    prefsStorage = new PrefsStorage(context);

    addCipherStorageToMap(new CipherStorageKeystoreAesCbc());


  }


  /** Allow initialization in chain. */
  public static Keychain withWarming(@NonNull final Context context) {
    final Keychain instance = new Keychain(context);

    // force initialization of the crypto api in background thread
    final Thread warmingUp = new Thread(instance::internalWarmingBestCipher, "keychain-warming-up");
    warmingUp.setDaemon(true);
    warmingUp.start();

    return instance;
  }

  /** cipher (crypto api) warming up logic. force java load classes and intializations. */
  private void internalWarmingBestCipher() {
    try {
      final long startTime = System.nanoTime();

      Log.v(KEYCHAIN_MODULE, "warming up started at " + startTime);
      final CipherStorageBase best = (CipherStorageBase) getCipherStorageForCurrentAPILevel();
      final Cipher instance = best.getCachedInstance();
      final boolean isSecure = best.supportsSecureHardware();
      final SecurityLevel requiredLevel = isSecure ? SecurityLevel.SECURE_HARDWARE : SecurityLevel.SECURE_SOFTWARE;
      best.generateKeyAndStoreUnderAlias("warmingUp", requiredLevel);
      best.getKeyStoreAndLoad();

      Log.v(KEYCHAIN_MODULE, "warming up takes: " +
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime) +
        " ms");
    } catch (Throwable ex) {
      Log.e(KEYCHAIN_MODULE, "warming up failed!", ex);
    }
  }
  //endregion

  //region Overrides



  //endregion

  public void setGenericPassword(@NonNull final String alias,
                                    @NonNull final String username,
                                    @NonNull final String password,
                                    @Nullable final HashMap<String, String> options) {
    try {
      throwIfEmptyLoginPassword(username, password);

      final SecurityLevel level = getSecurityLevelOrDefault(options);
      final CipherStorage storage = getSelectedStorage(options);

      throwIfInsufficientLevel(storage, level);

      final EncryptionResult result = storage.encrypt(alias, username, password, level);
      prefsStorage.storeEncryptedEntry(alias, result);

    } catch (Throwable e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage(), e);
    }
  }

  /** Get Cipher storage instance based on user provided options. */
  @NonNull
  private CipherStorage getSelectedStorage(@Nullable final HashMap<String, String> options)
    throws CryptoFailedException {
    final String accessControl = getAccessControlOrDefault(options);
    final boolean useBiometry = getUseBiometry(accessControl);
    final String cipherName = getSpecificStorageOrDefault(options);

    CipherStorage result = null;

    if (null != cipherName) {
      result = getCipherStorageByName(cipherName);
    }

    // attempt to access none existing storage will force fallback logic.
    if (null == result) {
      result = getCipherStorageForCurrentAPILevel(useBiometry);
    }

    return result;
  }

  public String getGenericPassword(@NonNull final String alias, @Nullable final HashMap options) {
    try {
      final ResultSet resultSet = prefsStorage.getEncryptedEntry(alias);
      final CipherStorage current = getCipherStorageForCurrentAPILevel(false);
      final String rules = getSecurityRulesOrDefault(options);

      final DecryptionResult decryptionResult = decryptCredentials(alias, current, resultSet, rules);
      return decryptionResult.password;

    } catch (KeyStoreAccessException | CryptoFailedException e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage());

    } catch (Throwable fail) {
      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);

    }
    return null;
  }

//  protected HashMap<String, String> getGenericPassword(@NonNull final String alias,
//                                    @Nullable final HashMap options) {
//    HashMap<String, String> credentials = new HashMap<>();
//    try {
//      final ResultSet resultSet = prefsStorage.getEncryptedEntry(alias);
//
//      if (resultSet == null) {
//        Log.e(KEYCHAIN_MODULE, "No entry found for service: " + alias);
////        promise.resolve(false);
//        return null;
//      }
//
//      // get the best storage
//      final String accessControl = getAccessControlOrDefault(options);
//      final boolean useBiometry = getUseBiometry(accessControl);
//      final CipherStorage current = getCipherStorageForCurrentAPILevel(useBiometry);
//      final String rules = getSecurityRulesOrDefault(options);
//
//      final DecryptionResult decryptionResult = decryptCredentials(alias, current, resultSet, rules);
//
//      credentials.put(Maps.SERVICE, alias);
//      credentials.put(Maps.USERNAME, decryptionResult.username);
//      credentials.put(Maps.PASSWORD, decryptionResult.password);
//      credentials.put(Maps.STORAGE, current.getCipherStorageName());
//
//      return credentials;
//    } catch (KeyStoreAccessException e) {
//      Log.e(KEYCHAIN_MODULE, e.getMessage());
//
//    } catch (CryptoFailedException e) {
//      Log.e(KEYCHAIN_MODULE, e.getMessage());
//
//    } catch (Throwable fail) {
//      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);
//
//    }
//    return null;
//  }


  public void resetGenericPassword(@NonNull final String alias) {
    try {
      // First we clean up the cipher storage (using the cipher storage that was used to store the entry)
      final ResultSet resultSet = prefsStorage.getEncryptedEntry(alias);

      if (resultSet != null) {
        final CipherStorage cipherStorage = getCipherStorageByName(resultSet.cipherStorageName);

        if (cipherStorage != null) {
          cipherStorage.removeKey(alias);
        }
      }
      // And then we remove the entry in the shared preferences
      prefsStorage.removeEntry(alias);

    } catch (KeyStoreAccessException e) {
      Log.e(KEYCHAIN_MODULE, e.getMessage());

    } catch (Throwable fail) {
      Log.e(KEYCHAIN_MODULE, fail.getMessage(), fail);

    }
  }

  //region Helpers

  /** Get service value from options. */
  @NonNull
  private static String getServiceOrDefault(@Nullable final HashMap<String, String> options) {
    String service = null;

    if (null != options && options.containsKey(Maps.SERVICE)) {
      service = options.get(Maps.SERVICE);
    }

    return getAliasOrDefault(service);
  }

  /** Get automatic secret manipulation rules, default: Automatic Upgrade. */
  @Rules
  @NonNull
  private static String getSecurityRulesOrDefault(@Nullable final HashMap options) {
    return getSecurityRulesOrDefault(options, Rules.AUTOMATIC_UPGRADE);
  }

  /** Get automatic secret manipulation rules. */
  @Rules
  @NonNull
  private static String getSecurityRulesOrDefault(@Nullable final HashMap<String, String> options,
                                                  @Rules @NonNull final String rule) {
    String rules = null;

    if (null != options && options.containsKey(Maps.RULES)) {
      rules = options.get(Maps.ACCESS_CONTROL);
    }

    if (null == rules) return rule;

    return rules;
  }

  /** Extract user specified storage from options. */
  @KnownCiphers
  @Nullable
  private static String getSpecificStorageOrDefault(@Nullable final HashMap<String, String> options) {
    String storageName = null;

    if (null != options && options.containsKey(Maps.STORAGE)) {
      storageName = options.get(Maps.STORAGE);
    }

    return storageName;
  }

  /** Get access control value from options or fallback to {@link AccessControl#NONE}. */
  @AccessControl
  @NonNull
  private static String getAccessControlOrDefault(@Nullable final HashMap options) {
    return getAccessControlOrDefault(options, AccessControl.NONE);
  }

  /** Get access control value from options or fallback to default. */
  @AccessControl
  @NonNull
  private static String getAccessControlOrDefault(@Nullable final HashMap<String, String> options,
                                                  @AccessControl @NonNull final String fallback) {
    String accessControl = null;

    if (null != options && options.containsKey(Maps.ACCESS_CONTROL)) {
      accessControl = options.get(Maps.ACCESS_CONTROL);
    }

    if (null == accessControl) return fallback;

    return accessControl;
  }


  /** Get security level from options or fallback {@link SecurityLevel#ANY} value. */
  @NonNull
  private static SecurityLevel getSecurityLevelOrDefault(@Nullable final HashMap options) {
    return getSecurityLevelOrDefault(options, SecurityLevel.ANY.name());
  }

  /** Get security level from options or fallback to default value. */
  @NonNull
  private static SecurityLevel getSecurityLevelOrDefault(@Nullable final HashMap<String, String> options,
                                                         @NonNull final String fallback) {
    String minimalSecurityLevel = null;

    if (null != options && options.containsKey(Maps.SECURITY_LEVEL)) {
      minimalSecurityLevel = options.get(Maps.SECURITY_LEVEL);
    }

    if (null == minimalSecurityLevel) minimalSecurityLevel = fallback;

    return SecurityLevel.valueOf(minimalSecurityLevel);
  }
  //endregion

  //region Implementation

  /** Is provided access control string matching biometry use request? */
  public static boolean getUseBiometry(@AccessControl @Nullable final String accessControl) {
    return AccessControl.BIOMETRY_ANY.equals(accessControl)
      || AccessControl.BIOMETRY_CURRENT_SET.equals(accessControl)
      || AccessControl.BIOMETRY_ANY_OR_DEVICE_PASSCODE.equals(accessControl)
      || AccessControl.BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE.equals(accessControl);
  }

  private void addCipherStorageToMap(@NonNull final CipherStorage cipherStorage) {
    cipherStorageMap.put(cipherStorage.getCipherStorageName(), cipherStorage);
  }


  /**
   * Extract credentials from current storage. In case if current storage is not matching
   * results set then executed migration.
   */
  @NonNull
  private DecryptionResult decryptCredentials(@NonNull final String alias,
                                              @NonNull final CipherStorage current,
                                              @NonNull final ResultSet resultSet,
                                              @Rules @NonNull final String rules)
    throws CryptoFailedException, KeyStoreAccessException {
    final String storageName = resultSet.cipherStorageName;

    // The encrypted data is encrypted using the current CipherStorage, so we just decrypt and return
    if (storageName.equals(current.getCipherStorageName())) {
      return decryptToResult(alias, current, resultSet);
    }

    // The encrypted data is encrypted using an older CipherStorage, so we need to decrypt the data first,
    // then encrypt it using the current CipherStorage, then store it again and return
    final CipherStorage oldStorage = getCipherStorageByName(storageName);
    if (null == oldStorage) {
      throw new KeyStoreAccessException("Wrong cipher storage name '" + storageName + "' or cipher not available");
    }

    // decrypt using the older cipher storage
    final DecryptionResult decryptionResult = decryptToResult(alias, oldStorage, resultSet);

    if (Rules.AUTOMATIC_UPGRADE.equals(rules)) {
      Log.d("AUTOMATIC HERE", "XXX");
      try {
        // encrypt using the current cipher storage
        migrateCipherStorage(alias, current, oldStorage, decryptionResult);
      } catch (CryptoFailedException e) {
        Log.w(KEYCHAIN_MODULE, "Migrating to a less safe storage is not allowed. Keeping the old one");
      }
    }

    return decryptionResult;
  }

  /** Try to decrypt with provided storage. */
  @NonNull
  private DecryptionResult decryptToResult(@NonNull final String alias,
                                           @NonNull final CipherStorage storage,
                                           @NonNull final ResultSet resultSet)
    throws CryptoFailedException {
    final DecryptionResultHandler handler = getInteractiveHandler(storage);
    storage.decrypt(handler, alias, resultSet.username, resultSet.password, SecurityLevel.ANY);

    CryptoFailedException.reThrowOnError(handler.getError());

    if (null == handler.getResult()) {
      throw new CryptoFailedException("No decryption results and no error. Something deeply wrong!");
    }

    return handler.getResult();
  }

  /** Get instance of handler that resolves access to the keystore on system request. */
  @NonNull
  protected DecryptionResultHandler getInteractiveHandler(@NonNull final CipherStorage current) {
    return new CipherStorageKeystoreAesCbc.NonInteractiveHandler();
  }

  /** Remove key from old storage and add it to the new storage. */
  /* package */ void migrateCipherStorage(@NonNull final String service,
                                          @NonNull final CipherStorage newCipherStorage,
                                          @NonNull final CipherStorage oldCipherStorage,
                                          @NonNull final DecryptionResult decryptionResult)
    throws KeyStoreAccessException, CryptoFailedException {

    // don't allow to degrade security level when transferring, the new
    // storage should be as safe as the old one.
    final EncryptionResult encryptionResult = newCipherStorage.encrypt(
      service, decryptionResult.username, decryptionResult.password,
      decryptionResult.getSecurityLevel());

    // store the encryption result
    prefsStorage.storeEncryptedEntry(service, encryptionResult);

    // clean up the old cipher storage
    oldCipherStorage.removeKey(service);
  }

  /**
   * The "Current" CipherStorage is the cipherStorage with the highest API level that is
   * lower than or equal to the current API level
   */
  @NonNull
  /* package */ CipherStorage getCipherStorageForCurrentAPILevel() throws CryptoFailedException {
    return getCipherStorageForCurrentAPILevel(true);
  }

  /**
   * The "Current" CipherStorage is the cipherStorage with the highest API level that is
   * lower than or equal to the current API level. Parameter allow to reduce level.
   */
  @NonNull
  /* package */ CipherStorage getCipherStorageForCurrentAPILevel(final boolean useBiometry)
    throws CryptoFailedException {
    final int currentApiLevel = Build.VERSION.SDK_INT;
    CipherStorage foundCipher = null;

    for (CipherStorage variant : cipherStorageMap.values()) {
      Log.d(KEYCHAIN_MODULE, "Probe cipher storage: " + variant.getClass().getSimpleName());

      // Is the cipherStorage supported on the current API level?
      final int minApiLevel = variant.getMinSupportedApiLevel();
      final int capabilityLevel = variant.getCapabilityLevel();
      final boolean isSupportedApi = (minApiLevel <= currentApiLevel);

      // API not supported
      if (!isSupportedApi) continue;

      // Is the API level better than the one we previously selected (if any)?
      if (foundCipher != null && capabilityLevel < foundCipher.getCapabilityLevel()) continue;


      // remember storage with the best capabilities
      foundCipher = variant;
    }

    if (foundCipher == null) {
      throw new CryptoFailedException("Unsupported Android SDK " + Build.VERSION.SDK_INT);
    }

    Log.d(KEYCHAIN_MODULE, "Selected storage: " + foundCipher.getClass().getSimpleName());

    return foundCipher;
  }

  /** Throw exception in case of empty credentials providing. */
  public static void throwIfEmptyLoginPassword(@Nullable final String username,
                                               @Nullable final String password)
    throws EmptyParameterException {
    if (TextUtils.isEmpty(username) || TextUtils.isEmpty(password)) {
      throw new EmptyParameterException("you passed empty or null username/password");
    }
  }

  /** Throw exception if required security level does not match storage provided security level. */
  public static void throwIfInsufficientLevel(@NonNull final CipherStorage storage,
                                              @NonNull final SecurityLevel level)
    throws CryptoFailedException {
    if (storage.securityLevel().satisfiesSafetyThreshold(level)) {
      return;
    }

    throw new CryptoFailedException(
      String.format(
        "Cipher Storage is too weak. Required security level is: %s, but only %s is provided",
        level.name(),
        storage.securityLevel().name()));
  }

  /** Extract cipher by it unique name. {@link CipherStorage#getCipherStorageName()}. */
  @Nullable
  /* package */ CipherStorage getCipherStorageByName(@KnownCiphers @NonNull final String knownName) {
    return cipherStorageMap.get(knownName);
  }


  /** Is secured hardware a part of current storage or not. */
  /* package */ boolean isSecureHardwareAvailable() {
    try {
      return getCipherStorageForCurrentAPILevel().supportsSecureHardware();
    } catch (CryptoFailedException e) {
      return false;
    }
  }

  /** Resolve storage to security level it provides. */
  @NonNull
  private SecurityLevel getSecurityLevel(final boolean useBiometry) {
    try {
      final CipherStorage storage = getCipherStorageForCurrentAPILevel(useBiometry);

      if (!storage.securityLevel().satisfiesSafetyThreshold(SecurityLevel.SECURE_SOFTWARE)) {
        return SecurityLevel.ANY;
      }

      if (storage.supportsSecureHardware()) {
        return SecurityLevel.SECURE_HARDWARE;
      }

      return SecurityLevel.SECURE_SOFTWARE;
    } catch (CryptoFailedException e) {
      Log.w(KEYCHAIN_MODULE, "Security Level Exception: " + e.getMessage(), e);

      return SecurityLevel.ANY;
    }
  }

  @NonNull
  private static String getAliasOrDefault(@Nullable final String service) {
    return service == null ? EMPTY_STRING : service;
  }
  //endregion

  //region Nested declarations

  //endregion
}
