/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.main;

import android.content.Context;
import android.preference.PreferenceManager;

import androidx.annotation.NonNull;

import com.stiiick.stickprotocol.cipherstream.CipherFile;
import com.stiiick.stickprotocol.cipherstream.CipherFileStream;
import com.stiiick.stickprotocol.cipherstream.CipherInputStream;
import com.stiiick.stickprotocol.cipherstream.CipherOutputStreamFactory;
import com.stiiick.stickprotocol.cipherstream.DigestingOutputStream;
import com.stiiick.stickprotocol.cipherstream.PaddingInputStream;
import com.stiiick.stickprotocol.database.DatabaseFactory;
import com.stiiick.stickprotocol.database.IdentityKeyRecord;
import com.stiiick.stickprotocol.keychain.Keychain;
import com.stiiick.stickprotocol.recipient.LiveRecipientCache;
import com.stiiick.stickprotocol.store.MySenderKeyStore;
import com.stiiick.stickprotocol.store.MyProtocolStore;
import com.stiiick.stickprotocol.util.Base64;
import com.stiiick.stickprotocol.util.IdentityKeyUtil;
import com.stiiick.stickprotocol.util.PreKeyUtil;
import com.stiiick.stickprotocol.util.Preferences;
import com.stiiick.stickprotocol.util.Util;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.signal.argon2.Argon2;
import org.signal.argon2.Argon2Exception;
import org.signal.argon2.Type;
import org.signal.argon2.Version;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.groups.GroupCipher;
import org.whispersystems.libsignal.groups.GroupSessionBuilder;
import org.whispersystems.libsignal.groups.SenderKeyName;
import org.whispersystems.libsignal.groups.state.SenderKeyRecord;
import org.whispersystems.libsignal.groups.state.SenderKeyState;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static java.lang.Long.parseLong;

/*
    This is the main StickProtocol class.
    Using this class, you have access to all of the StickProtocol methods you would need.

    @author Omar Basem
 */

public class StickProtocol {
    private static Context context;
    private static String path;
    private static LiveRecipientCache recipientCache;
    private final Keychain keychain;
    private final String service;
    private final String passwordKey;

    /***
     * The StickProtocol constructor takes 2 arguments, the application context, and the application
     * package name as a string ("com.myOrg.myApp")
     */

    public StickProtocol(Context context, String service) {
        StickProtocol.context = context;
        path = context.getFilesDir().getPath();
        keychain = new Keychain(context);
        this.service = service;
        this.passwordKey = service + ".password";
    }

    /****************************** START OF INITIALIZATION METHODS ******************************/

    /***
     * The StickProtocol initialization method. To be called for every user once at registration time.
     *
     * @param userId - String, unique userId
     * @param password - String, user's plaintext password
     * @param progressEvent - (optional) A ProgressEvent interface can be implemented to provide progress
     *                      feedback to the user while the keys are being generated.
     * @return JSONObject - contains the following:
     *                          * 1 Identity key
     *                          * 1 Signed prekey
     *                          * 10 prekeys
     *                          * localId
     *                          * oneTimeId
     *                          * initial password hash
     *                          * password salt
     */
    public JSONObject initialize(String userId, String password, ProgressEvent progressEvent) {
        try {
            // Store the user's password in BlockStore/KeyStore
            HashMap<String, String> serviceMap = new HashMap();
            serviceMap.put("service", passwordKey);
            keychain.setGenericPassword(userId, userId, password, serviceMap);

            // Generate password salt
            SecureRandom randomSalt = new SecureRandom();
            byte[] salt = new byte[32];
            randomSalt.nextBytes(salt);

            // Hashing pass using Argon2
            byte[] passwordHashBytes = new Argon2.Builder(Version.V13)
                    .type(Type.Argon2id)
                    .memoryCostKiB(4 * 1024)
                    .parallelism(2)
                    .iterations(3)
                    .hashLength(32)
                    .build()
                    .hash(password.getBytes(), salt)
                    .getHash();
            String passwordHash = Base64.encodeBytes(passwordHashBytes);

            SignalProtocolStore store = new MyProtocolStore(context);
            IdentityKeyUtil.generateIdentityKeys(context);
            IdentityKeyPair identityKey = store.getIdentityKeyPair();
            SignedPreKeyRecord signedPreKey = PreKeyUtil.generateSignedPreKey(context, identityKey, true);
            List<PreKeyRecord> preKeys = PreKeyUtil.generatePreKeys(context, 0, 10);
            JSONArray preKeysArray = new JSONArray();
            for (int i = 1; i < preKeys.size(); i++) {
                JSONObject preKey = new JSONObject();
                preKey.put("id", preKeys.get(i).getId());
                preKey.put("public", Base64.encodeBytes(preKeys.get(i).getKeyPair().getPublicKey().serialize()));
                HashMap<String, String> cipherMap = pbEncrypt(preKeys.get(i).getKeyPair().getPrivateKey().serialize(), password);
                preKey.put("cipher", cipherMap.get("cipher"));
                preKey.put("salt", cipherMap.get("salt"));
                preKeysArray.put(preKey);

                // PROGRESS
                if (progressEvent != null) {
                    JSONObject event = new JSONObject();
                    event.put("progress", i + 1);
                    event.put("total", preKeys.size());
                    progressEvent.execute(event);
                }
            }

            JSONObject signedPreKeyJson = new JSONObject();
            signedPreKeyJson.put("id", Preferences.getActiveSignedPreKeyId(context));
            signedPreKeyJson.put("public", Base64.encodeBytes(signedPreKey.getKeyPair().getPublicKey().serialize()));
            signedPreKeyJson.put("signature", Base64.encodeBytes(signedPreKey.getSignature()));
            HashMap<String, String> signedCipherMap = pbEncrypt(signedPreKey.getKeyPair().getPrivateKey().serialize(), password);
            signedPreKeyJson.put("cipher", signedCipherMap.get("cipher"));
            signedPreKeyJson.put("salt", signedCipherMap.get("salt"));
            signedPreKeyJson.put("timestamp", Long.toString(signedPreKey.getTimestamp()));

            JSONObject identityKeyJson = new JSONObject();
            identityKeyJson.put("id", Preferences.getActiveIdentityKeyId(context));
            identityKeyJson.put("public", Base64.encodeBytes(identityKey.getPublicKey().serialize()));
            HashMap<String, String> identityCipherMap = pbEncrypt(identityKey.getPrivateKey().serialize(), password);
            identityKeyJson.put("cipher", identityCipherMap.get("cipher"));
            identityKeyJson.put("salt", identityCipherMap.get("salt"));
            identityKeyJson.put("timestamp", Preferences.getActiveIdentityKeyTimestamp(context));

            String oneTimeId = UUID.randomUUID().toString();
            int localId = KeyHelper.generateRegistrationId(false);
            Preferences.setLocalRegistrationId(context, localId);
            JSONObject map = new JSONObject();
            map.put("identityKey", identityKeyJson);
            map.put("signedPreKey", signedPreKeyJson);
            map.put("preKeys", preKeysArray);
            map.put("passwordHash", passwordHash);
            map.put("passwordSalt", Base64.encodeBytes(salt));
            map.put("oneTimeId", oneTimeId);
            map.put("localId", localId);

            PreferenceManager.getDefaultSharedPreferences(context).edit().putString("oneTimeId", oneTimeId).apply();
            PreferenceManager.getDefaultSharedPreferences(context).edit().putString("userId", userId).apply();

            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, 0);
            SessionBuilder sessionBuilder = new SessionBuilder(store, signalProtocolAddress);
            ECPublicKey preKey = Curve.decodePoint(preKeys.get(0).getKeyPair().getPublicKey().serialize(), 0);

            PreKeyBundle preKeyBundle = new PreKeyBundle(
                    store.getLocalRegistrationId(),
                    0,
                    preKeys.get(0).getId(),
                    preKey,
                    signedPreKey.getId(),
                    signedPreKey.getKeyPair().getPublicKey(),
                    signedPreKey.getSignature(),
                    identityKey.getPublicKey()
            );
            sessionBuilder.process(preKeyBundle);
            return map;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /***
     * The StickProtocol Re-Initialize method to decrypt the user's keys and re-establish the sticky
     * sessions. Needs to be called once, at login time.
     *
     * @param bundle - JSONObject that needs to contain the following:
     *               * An array of identity keys
     *               * An array of signed prekeys
     *               * An array of prekeys
     *               * An array of sender keys (EncryptingSenderKeys)
     *               * localId
     * @param password - String, user's plaintext password
     * @param userId - String, user's unique id
     * @param oneTimeId - String, a newly generated uuid for the user
     * @param progressEvent - (optional) A ProgressEvent interface can be implemented to provide progress
     *                        feedback to the user while the keys are being decrypted and the sessions
     *                        re-established.
     */
    public void reInitialize(JSONObject bundle, String password, String userId, String oneTimeId, ProgressEvent progressEvent) {
        try {
            PreferenceManager.getDefaultSharedPreferences(context).edit().putString("oneTimeId", oneTimeId).apply();
            PreferenceManager.getDefaultSharedPreferences(context).edit().putString("userId", userId).apply();

            // Store password in BlockStore/KeyStore
            HashMap<String, String> serviceMap = new HashMap();
            serviceMap.put("service", context.getPackageName());
            keychain.setGenericPassword(userId, userId, password, serviceMap);


            SignalProtocolStore store = new MyProtocolStore(context);
            Preferences.setLocalRegistrationId(context, bundle.getInt("localId"));
            JSONArray preKeys = (JSONArray) bundle.get("preKeys");
            JSONArray senderKeys = (JSONArray) bundle.get("senderKeys");
            JSONArray signedPreKeys = (JSONArray) bundle.get("signedPreKeys");
            JSONArray identityKeys = (JSONArray) bundle.get("identityKeys");
            int totalKeys = identityKeys.length() + signedPreKeys.length() + preKeys.length() + senderKeys.length();
            int progress = 0;

            for (int i = 0; i < identityKeys.length(); i++) {
                JSONObject IKJson = identityKeys.getJSONObject(i);
                IdentityKey publicKey = new IdentityKey(Base64.decode((String) IKJson.getString("public")), 0);
                byte[] identityCipher = pbDecrypt((String) IKJson.getString("cipher"), (String) IKJson.getString("salt"), password);
                ECPrivateKey privateKey = Curve.decodePrivatePoint(identityCipher);
                ECKeyPair ecKeyPair = new ECKeyPair(publicKey.getPublicKey(), privateKey);
                int identityKeyId = IKJson.getInt("id");
                IdentityKeyRecord identityKeyRecord = new IdentityKeyRecord(identityKeyId, parseLong(IKJson.getString("timestamp")), ecKeyPair);
                DatabaseFactory.getIdentityKeyDatabase(context).insertIdentityKey(identityKeyId, identityKeyRecord);
                if (IKJson.getBoolean("active")) {
                    IdentityKeyUtil.save(context, "pref_identity_public", Base64.encodeBytes(publicKey.serialize()));
                    IdentityKeyUtil.save(context, "pref_identity_private", Base64.encodeBytes(privateKey.serialize()));
                    Preferences.setNextIdentityKeyId(context, identityKeyId + 1);
                    Preferences.setActiveIdentityKeyId(context, identityKeyId);
                    Preferences.setActiveIdentityKeyTimestamp(context, parseLong(IKJson.getString("timestamp")));
                }

                // PROGRESS
                progress += 1;
                if (progressEvent != null) {
                    JSONObject event = new JSONObject();
                    event.put("progress", progress);
                    event.put("total", totalKeys);
                    progressEvent.execute(event);
                }
            }

            for (int i = 0; i < signedPreKeys.length(); i++) {
                JSONObject SPKJson = signedPreKeys.getJSONObject(i);
                ECPublicKey sigPublicKey = Curve.decodePoint(Base64.decode((String) SPKJson.getString("public")), 0);
                byte[] signedCipher = pbDecrypt((String) SPKJson.getString("cipher"), (String) SPKJson.getString("salt"), password);
                ECPrivateKey sigPrivateKey = Curve.decodePrivatePoint(signedCipher);
                ECKeyPair sigKeyPair = new ECKeyPair(sigPublicKey, sigPrivateKey);
                int signedPreKeId = (int) SPKJson.get("id");
                SignedPreKeyRecord record = new SignedPreKeyRecord(signedPreKeId, parseLong(SPKJson.getString("timestamp")), sigKeyPair, Base64.decode(SPKJson.getString("signature")));
                store.storeSignedPreKey(signedPreKeId, record);
                if (SPKJson.getBoolean("active")) {
                    Preferences.setActiveSignedPreKeyId(context, signedPreKeId);
                    Preferences.setActiveSignedPreKeyTimestamp(context, parseLong(SPKJson.getString("timestamp")));
                    Preferences.setNextSignedPreKeyId(context, signedPreKeId + 1);
                }

                // PROGRESS
                progress += 1;
                if (progressEvent != null) {
                    JSONObject event = new JSONObject();
                    event.put("progress", progress);
                    event.put("total", totalKeys);
                    progressEvent.execute(event);
                }
            }

            for (int i = 0; i < preKeys.length(); i++) {
                JSONObject preKeyJson = preKeys.getJSONObject(i);
                ECPublicKey prePubKey = Curve.decodePoint(Base64.decode(preKeyJson.getString("public")), 0);
                byte[] cipher = pbDecrypt(preKeyJson.getString("cipher"), preKeyJson.getString("salt"), password);
                ECPrivateKey prePrivKey = Curve.decodePrivatePoint(cipher);
                ECKeyPair preKey = new ECKeyPair(prePubKey, prePrivKey);
                PreKeyRecord pkRecord = new PreKeyRecord(preKeyJson.getInt("id"), preKey);
                store.storePreKey(preKeyJson.getInt("id"), pkRecord);

                // PROGRESS
                progress += 1;
                if (progressEvent != null) {
                    JSONObject event = new JSONObject();
                    event.put("progress", progress);
                    event.put("total", totalKeys);
                    progressEvent.execute(event);
                }
            }

            // OWN SENDER KEYS
            for (int i = 0; i < senderKeys.length(); i++) {
                JSONObject senderKeyJson = senderKeys.getJSONObject(i);
                reinitMyStickySession(userId, senderKeyJson);

                // PROGRESS
                progress += 1;
                if (progressEvent != null) {
                    JSONObject event = new JSONObject();
                    event.put("progress", progress);
                    event.put("total", totalKeys);
                    progressEvent.execute(event);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /***
     * This method is used to create the initial password hash using Argon2, from a provided password
     * and salt, at login.
     *
     * @param password - String, plaintext password
     * @param salt - String, the salt that was used to create the initial password hash at registration time.
     *
     * @return initial password hash - String
     */
    public String createPasswordHash(String password, String salt) throws IOException, Argon2Exception {
        byte[] passwordHashBytes = new Argon2.Builder(Version.V13)
                .type(Type.Argon2id)
                .memoryCostKiB(4 * 1024)
                .parallelism(2)
                .iterations(3)
                .hashLength(32)
                .build()
                .hash(password.getBytes(), Base64.decode(salt))
                .getHash();
        return Base64.encodeBytes(passwordHashBytes);
    }

    /***
     * An interface with a method "execute" to be implemented to provide progress feedback to the user
     * during the initialize() and reInitialize() methods.
     */
    public interface ProgressEvent {
        void execute(JSONObject event);
    }

    /****************************** END OF INITIALIZATION METHODS ******************************/

    /************* START OF PAIRWISE SESSION METHODS REQUIRED BY STICKY SESSIONS *****************/

    /***
     * This method is used to initialize a Signal pairwise session.
     *
     * @param bundle - JSONObject that should contain the following:
     *               * userId - String
     *               * localId - int
     *               * identityKey (public) - String
     *               * signedPreKey (public) - String
     *               * signedPreKeyId - int
     *               * signature - String
     *               * preKey (public) - String
     *               * preKeyId - int
     *
     */
    public void initPairwiseSession(JSONObject bundle) {
        try {
            SignalProtocolStore store = new MyProtocolStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(bundle.getString("userId"), 0);
            SessionBuilder sessionBuilder = new SessionBuilder(store, signalProtocolAddress);
            ECPublicKey preKey = Curve.decodePoint(Base64.decode(bundle.getString("preKey")), 0);
            ECPublicKey signedPreKey = Curve.decodePoint(Base64.decode(bundle.getString("signedPreKey")), 0);
            ECPublicKey identityKey = Curve.decodePoint(Base64.decode(bundle.getString("identityKey")), 0);
            IdentityKey identityPublicKey = new IdentityKey(identityKey);

            PreKeyBundle preKeyBundle = new PreKeyBundle(
                    bundle.getInt("localId"),
                    0,
                    bundle.getInt("preKeyId"),
                    preKey,
                    bundle.getInt("signedPreKeyId"),
                    signedPreKey,
                    Base64.decode(bundle.getString("signature")),
                    identityPublicKey
            );
            sessionBuilder.process(preKeyBundle);
        } catch (UntrustedIdentityException | InvalidKeyException | IOException | JSONException e) {
            e.printStackTrace();
        }
    }

    /***
     * This method is used to encrypt text in a pairwise session. Used to encrypt sender keys (sticky keys).
     *
     * @param userId - String
     * @param text - plaintext string to be encrypted
     */
    public String encryptTextPairwise(String userId, String text) {
        try {
            SignalProtocolStore store = new MyProtocolStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, 0);
            SessionCipher sessionCipher = new SessionCipher(store, signalProtocolAddress);
            CiphertextMessage cipher = sessionCipher.encrypt(text.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeBytes(cipher.serialize());
        } catch (UntrustedIdentityException e) {
            e.printStackTrace();
            return null;
        }
    }

    /***
     * This method is used to decrypt text in a pairwise session. Used to decrypt sender keys (sticky keys).
     *
     * @param senderId - String, the userId of the sender
     * @param isStickyKey - boolean, indicates whether the cipher text is a sticky key
     * @param cipher - String, ciphertext to be decrypted
     * @return plaintext - String
     */
    public String decryptTextPairwise(String senderId, boolean isStickyKey, String cipher) {
        try {
            SignalProtocolStore store = new MyProtocolStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, 0);
            SessionCipher sessionCipher = new SessionCipher(store, signalProtocolAddress);
            byte[] bytes;
            if (!store.containsSession(signalProtocolAddress) || isStickyKey) {
                PreKeySignalMessage preKeySignalMessage = new PreKeySignalMessage(Base64.decode(cipher));
                bytes = sessionCipher.decrypt(preKeySignalMessage);
            } else {
                SignalMessage signalMessage = new SignalMessage(Base64.decode(cipher));
                bytes = sessionCipher.decrypt(signalMessage);
            }
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (InvalidMessageException | DuplicateMessageException | LegacyMessageException
                | UntrustedIdentityException | InvalidVersionException | InvalidKeyIdException
                | InvalidKeyException | NoSessionException | IOException e) {
            e.printStackTrace();
            SignalProtocolStore store = new MyProtocolStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, 0);
            SessionCipher sessionCipher = new SessionCipher(store, signalProtocolAddress);
            byte[] bytes = null;
            try {
                PreKeySignalMessage preKeySignalMessage = new PreKeySignalMessage(Base64.decode(cipher));
                bytes = sessionCipher.decrypt(preKeySignalMessage);
            } catch (DuplicateMessageException | LegacyMessageException | InvalidMessageException
                    | InvalidKeyIdException | InvalidKeyException | UntrustedIdentityException
                    | InvalidVersionException | IOException ex) {
                ex.printStackTrace();
            }
            if (bytes != null)
                return new String(bytes, StandardCharsets.UTF_8);
            else
                return null;
        }
    }


    /************* END OF PAIRWISE SESSION METHODS REQUIRED BY STICKY SESSIONS *****************/

    /****************************** START OF STICKY SESSION METHODS ******************************/

    /***
     * This method is used to create a sticky session and get the EncryptingSenderKey of a user for a party.
     *
     * @param userId
     * @param stickId - String, the stickId of the sticky session
     * @return JSONObject - contains the following:
     *                          * id - int, the sender key id
     *                          * chainKey - String
     *                          * public - String, signature key public key
     *                          * cipher - String, signature key encrypted private key
     */
    public JSONObject getEncryptingSenderKey(String userId, String stickId) {
        try {
            SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, 0);
            SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
            GroupSessionBuilder groupSessionBuilder = new GroupSessionBuilder(senderKeyStore);
            SenderKeyDistributionMessage senderKeyDistributionMessage = groupSessionBuilder.create(senderKeyName);
            DatabaseFactory.getStickyKeyDatabase(context).insertStickyKey(stickId, Base64.encodeBytes(senderKeyDistributionMessage.serialize()));
            SenderKeyState senderKeyState = senderKeyStore.loadSenderKey(senderKeyName).getSenderKeyState();
            String cipher = encryptTextPairwise(userId, Base64.encodeBytes(senderKeyState.getSigningKeyPrivate().serialize()));
            JSONObject map = new JSONObject();
            map.put("id", senderKeyState.getKeyId());
            map.put("chainKey", Base64.encodeBytes(senderKeyState.getSenderChainKey().getSeed()));
            map.put("public", Base64.encodeBytes(senderKeyState.getSigningKeyPublic().serialize()));
            map.put("cipher", cipher);
            return map;
        } catch (InvalidKeyException | InvalidKeyIdException | JSONException e) {
            e.printStackTrace();
            return null;
        }
    }

    /***
     * This method is used to get a user's sender key (DecryptingSenderKey) of a sticky session (or a standard group session)
     * in order to share it with other members of a party.
     *
     * @param senderId - userId (or oneTimeId)
     * @param targetId - target userId (or oneTimeId)
     * @param stickId - the id of the sticky session (or standard session)
     * @param isSticky - boolean, indicates whether the sender key is for a sticky session or a standard group session
     * @return encrypted sender key to the target - String
     */
    public String getSenderKey(String senderId, String targetId, String stickId, Boolean isSticky) throws IOException, InvalidMessageException, LegacyMessageException {
        SenderKeyDistributionMessage senderKeyDistributionMessage = null;
        if (isSticky)
            senderKeyDistributionMessage = new SenderKeyDistributionMessage(Base64.decode(DatabaseFactory.getStickyKeyDatabase(context).getStickyKey(stickId)));
        else {
            SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, 0);
            SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
            GroupSessionBuilder groupSessionBuilder = new GroupSessionBuilder(senderKeyStore);
            senderKeyDistributionMessage = groupSessionBuilder.create(senderKeyName);
        }
        return encryptTextPairwise(targetId, Base64.encodeBytes(senderKeyDistributionMessage.serialize()));
    }

    /**
     * This method is used to create a sticky session from a sender key that was encrypted to the user.
     *
     * @param senderId        - userId of the sender
     * @param stickId         - id of the sticky session
     * @param cipherSenderKey - encrypted sender key
     * @param identityKeyId   - the identity key id of the target user that was used to encrypt the sender key
     */
    public void initSession(String senderId, String stickId, String cipherSenderKey, int identityKeyId) {
        try {
            if (cipherSenderKey != null) {
                SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
                SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, 0);
                SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
                GroupSessionBuilder groupSessionBuilder = new GroupSessionBuilder(senderKeyStore);
                String senderKey = decryptStickyKey(senderId, cipherSenderKey, identityKeyId);
                if (senderKey != null) {
                    SenderKeyDistributionMessage senderKeyDistributionMessage = new SenderKeyDistributionMessage(Base64.decode(senderKey));
                    groupSessionBuilder.process(senderKeyName, senderKeyDistributionMessage);
                }
            }
        } catch (InvalidMessageException | LegacyMessageException | IOException e) {
            e.printStackTrace();
        }
    }

    /***
     * This method is used to decrypt a sticky key (sender key). Before attempting to decrypt the ciphertext,
     * it will check and swap the current active identity key if needed.
     *
     * @param senderId - userId of the sender
     * @param cipher - the encrypted key
     * @param identityKeyId - the identity key id of the target user that was used to encrypt the sender key
     */
    public String decryptStickyKey(String senderId, String cipher, int identityKeyId) {
        int activeIdentityKeyId = Preferences.getActiveIdentityKeyId(context);
        // Swap identity key if needed
        if (activeIdentityKeyId != identityKeyId) {
            IdentityKeyRecord identityKeyRecord = DatabaseFactory.getIdentityKeyDatabase(context).getIdentityKey(identityKeyId);
            IdentityKeyUtil.save(context, "pref_identity_public", Base64.encodeBytes(identityKeyRecord.getKeyPair().getPublicKey().serialize()));
            IdentityKeyUtil.save(context, "pref_identity_private", Base64.encodeBytes(identityKeyRecord.getKeyPair().getPrivateKey().serialize()));
        }

        String key = decryptTextPairwise(senderId, true, cipher);

        // Reverse identity key back if was swapped
        if (activeIdentityKeyId != identityKeyId) {
            IdentityKeyRecord identityKeyRecord = DatabaseFactory.getIdentityKeyDatabase(context).getIdentityKey(Preferences.getActiveIdentityKeyId(context));
            IdentityKeyUtil.save(context, "pref_identity_public", Base64.encodeBytes(identityKeyRecord.getKeyPair().getPublicKey().serialize()));
            IdentityKeyUtil.save(context, "pref_identity_private", Base64.encodeBytes(identityKeyRecord.getKeyPair().getPrivateKey().serialize()));
        }
        return key;
    }

    /***
     * This method is used to make an encryption in a sticky session.
     *
     * @param senderId - userId (or oneTimeId)
     * @param stickId - id of the sticky session
     * @param text - plaintext to be encrypted
     * @param isSticky - boolean indicating whether this encryption is for a sticky session
     * @return ciphertext
     */
    public String encryptText(String senderId, String stickId, String text, Boolean isSticky) {
        try {
            SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, 0);
            SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
            GroupCipher groupCipher = new GroupCipher(senderKeyStore, senderKeyName);
            byte[] cipherText;
            cipherText = groupCipher.encrypt(text.getBytes(StandardCharsets.UTF_8), isSticky);
            return Base64.encodeBytes(cipherText);

        } catch (NoSessionException | InvalidMessageException | DuplicateMessageException e) {
            e.printStackTrace();
        }
        return null;
    }


    /***
     * This method is used to make a decryption in a sticky session
     *
     * @param senderId - id of the sender
     * @param stickId - id of the sticky session
     * @param cipher - ciphertext to be decrypted
     * @param isSticky - boolean indicating whether this decryption is for a sticky session
     */
    public String decryptText(String senderId, String stickId, String cipher, Boolean isSticky) {
        if (cipher.length() < 4)
            return null;
        try {
            Boolean isSelf = senderId.equals(PreferenceManager.getDefaultSharedPreferences(context).getString("userId", ""));
            SenderKeyStore mySenderKeyStore = new MySenderKeyStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, 0);
            SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
            GroupCipher groupCipher = new GroupCipher(mySenderKeyStore, senderKeyName);
            byte[] decryptedCipher;
            decryptedCipher = groupCipher.decrypt(Base64.decode(cipher), isSticky, isSelf);
            return new String(decryptedCipher, StandardCharsets.UTF_8);
        } catch (LegacyMessageException | InvalidMessageException | DuplicateMessageException
                | NoSessionException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }


    /***
     * This method is used to encrypt files in a sticky session
     *
     * @param senderId - userId
     * @param stickId - id of the sticky session
     * @param filePath - path of the file to be encrypted
     * @param contentMedia - type of the file
     * @param isSticky - boolean indicating whether this encryption is for a sticky sesison
     *
     * @return JSONObject - contains the following:
     *                          * uri: path of the encrypted file
     *                          * cipher: (fileKey||fileHash) encrypted
     */
    public JSONObject encryptFile(String senderId, String stickId, String filePath, String contentMedia, Boolean isSticky) throws JSONException {
        HashMap<String, String> hashMap = encryptMedia(filePath, contentMedia);
        String cipherText = encryptText(senderId, stickId, hashMap.get("secret"), isSticky);
        JSONObject map = new JSONObject();
        map.put("uri", hashMap.get("uri"));
        map.put("cipher", cipherText);
        return map;
    }


    /***
     * This method is used to decrypt files in a sticky session
     *
     * @param senderId - id of the sender
     * @param stickId - id of the sticky session
     * @param filePath - path of the encrypted file
     * @param cipher - (fileKey||fileHash) encrypted
     * @param outputPath - path to decrypt the file at
     * @param isSticky - boolean indicating whether this decryption is for a sticky session
     * @return absolute path of the decrypted file
     */
    public String decryptFile(String senderId, String stickId, String filePath, String cipher, String outputPath, Boolean isSticky) {
        String secret = decryptText(senderId, stickId, cipher, isSticky);
        String path = null;
        if (secret != null)
            path = decryptMedia(filePath, secret, outputPath);
        return path;
    }

    /***
     * This method is used to check if a sticky session exists.
     *
     * @param senderId - id of the sender
     * @param stickId - id of the sticky session
     * @return boolean
     */
    public Boolean sessionExists(String senderId, String stickId) {
        SenderKeyStore mySenderKeyStore = new MySenderKeyStore(context);
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, 0);
        SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
        SenderKeyRecord record = mySenderKeyStore.loadSenderKey(senderKeyName);
        return !record.isEmpty();
    }

    /***
     * This method is used to get the current chain step of a sticky session.
     *
     * @param userId
     * @param stickId - id of the sticky session
     * @return the chain step - int
     */
    public int getChainStep(String userId, String stickId) {
        SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, 0);
        SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
        try {
            int step = senderKeyStore.loadSenderKey(senderKeyName).getSenderKeyState().getSenderChainKey().getIteration();
            return step;
        } catch (InvalidKeyIdException e) {
            e.printStackTrace();
            return 9999;
        }
    }

    /***
     * This method is used to ratchet the chain of a sticky session, in order to be matching across all devices.
     *
     * @param userId
     * @param stickId - id of the sticky sesison
     * @param steps - number of steps
     */
    public void ratchetChain(String userId, String stickId, int steps) throws NoSessionException {
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, 0);
        SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
        SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
        GroupCipher groupCipher = new GroupCipher(senderKeyStore, senderKeyName);
        groupCipher.ratchetChain(steps);
    }

    /**
     * This method is used to re-establish a user's own sticky session.
     *
     * @param userId
     * @param senderKey - JSONObject, contains the following:
     *                      * id - int, id of the key
     *                      * chainKey - String
     *                      * public - String, public signature key
     *                      * cipher - String, encrypted private signature key
     *                      * stickId - String, id of the sticky session
     *                      * identityKeyId - int, id of the identity key used to encrypt the private signature key
     */
    public void reinitMyStickySession(String userId, JSONObject senderKey) throws IOException, InvalidKeyException, NoSessionException, JSONException {
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, 0);
        SenderKeyName senderKeyName = new SenderKeyName(senderKey.getString("stickId"), signalProtocolAddress);
        SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
        SenderKeyRecord senderKeyRecord = senderKeyStore.loadSenderKey(senderKeyName);
        ECPublicKey senderPubKey = Curve.decodePoint(Base64.decode(senderKey.getString("public")), 0);
        String privateKey = decryptStickyKey(userId, senderKey.getString("cipher"), senderKey.getInt("identityKeyId"));
        ECPrivateKey senderPrivKey = Curve.decodePrivatePoint(Base64.decode(privateKey));
        ECKeyPair signedSenderKey = new ECKeyPair(senderPubKey, senderPrivKey);
        senderKeyRecord.setSenderKeyState(
                senderKey.getInt("id"),
                0,
                Base64.decode(senderKey.getString("chainKey")),
                signedSenderKey
        );
        senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord);

        // Store initial sender key
        GroupSessionBuilder groupSessionBuilder = new GroupSessionBuilder(senderKeyStore);
        SenderKeyDistributionMessage senderKeyDistributionMessage = groupSessionBuilder.create(senderKeyName);
        DatabaseFactory.getStickyKeyDatabase(context).insertStickyKey(senderKey.getString("stickId"), Base64.encodeBytes(senderKeyDistributionMessage.serialize()));

        // RATCHET CHAIN
        GroupCipher groupCipher = new GroupCipher(senderKeyStore, senderKeyName);
        groupCipher.ratchetChain(senderKey.getInt("step"));
    }


    /****************************** END OF STICKY SESSION METHODS ******************************/

    /****************************** START OF USER KEYS METHODS ******************************/

    public JSONObject refreshIdentityKey(int days) throws Exception {
        long identityKeyAge = TimeUnit.MINUTES.toDays(days);
        long activeDuration = System.currentTimeMillis() - Preferences.getActiveIdentityKeyTimestamp(context);
        if (activeDuration > identityKeyAge) {
            SignalProtocolStore store = new MyProtocolStore(context);
            IdentityKeyUtil.generateIdentityKeys(context);
            IdentityKeyPair identityKey = store.getIdentityKeyPair();

            String userId = PreferenceManager.getDefaultSharedPreferences(context).getString("userId", "");
            HashMap<String, String> serviceMap = new HashMap();
            serviceMap.put("service", passwordKey);
            String password = keychain.getGenericPassword(userId, serviceMap);
            JSONObject identityKeyJson = new JSONObject();
            identityKeyJson.put("id", Preferences.getActiveIdentityKeyId(context));
            identityKeyJson.put("public", Base64.encodeBytes(identityKey.getPublicKey().serialize()));
            HashMap<String, String> signedCipherMap = pbEncrypt(identityKey.getPrivateKey().serialize(), password);
            identityKeyJson.put("cipher", signedCipherMap.get("cipher"));
            identityKeyJson.put("salt", signedCipherMap.get("salt"));
            identityKeyJson.put("timestamp", Long.toString(Preferences.getActiveIdentityKeyTimestamp(context)));
            return identityKeyJson;
        }
        return null;
    }

    public JSONObject refreshSignedPreKey(int days) throws Exception {
        long signedPreKeyAge = TimeUnit.MINUTES.toDays(days);
        long activeDuration = System.currentTimeMillis() - Preferences.getActiveSignedPreKeyTimestamp(context);
        if (activeDuration > signedPreKeyAge) {
            IdentityKeyPair identityKey = IdentityKeyUtil.getIdentityKeyPair(context);
            SignedPreKeyRecord signedPreKey = PreKeyUtil.generateSignedPreKey(context, identityKey, true);

            String userId = PreferenceManager.getDefaultSharedPreferences(context).getString("userId", "");
            HashMap<String, String> serviceMap = new HashMap();
            serviceMap.put("service", passwordKey);
            String password = keychain.getGenericPassword(userId, serviceMap);
            JSONObject signedPreKeyJson = new JSONObject();
            signedPreKeyJson.put("id", Preferences.getActiveSignedPreKeyId(context));
            signedPreKeyJson.put("public", Base64.encodeBytes(signedPreKey.getKeyPair().getPublicKey().serialize()));
            signedPreKeyJson.put("signature", Base64.encodeBytes(signedPreKey.getSignature()));
            HashMap<String, String> signedCipherMap = pbEncrypt(signedPreKey.getKeyPair().getPrivateKey().serialize(), password);
            signedPreKeyJson.put("cipher", signedCipherMap.get("cipher"));
            signedPreKeyJson.put("salt", signedCipherMap.get("salt"));
            signedPreKeyJson.put("timestamp", Long.toString(signedPreKey.getTimestamp()));
            return signedPreKeyJson;
        }
        return null;
    }

    public JSONArray generatePreKeys(int nextPreKeyId, int count) {
        try {
            String userId = PreferenceManager.getDefaultSharedPreferences(context).getString("userId", "");
            HashMap<String, String> serviceMap = new HashMap();
            serviceMap.put("service", passwordKey);
            String password = keychain.getGenericPassword(userId, serviceMap);
            List<PreKeyRecord> preKeys = PreKeyUtil.generatePreKeys(context, nextPreKeyId, count);
            JSONArray preKeysArray = new JSONArray();
            for (int i = 0; i < preKeys.size(); i++) {
                JSONObject preKey = new JSONObject();
                preKey.put("id", preKeys.get(i).getId());
                preKey.put("public", Base64.encodeBytes(preKeys.get(i).getKeyPair().getPublicKey().serialize()));
                HashMap<String, String> cipherMap = pbEncrypt(preKeys.get(i).getKeyPair().getPrivateKey().serialize(), password);
                preKey.put("cipher", cipherMap.get("cipher"));
                preKey.put("salt", cipherMap.get("salt"));
                preKeysArray.put(preKey);
            }
            return preKeysArray;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /****************************** END OF USER KEYS METHODS ******************************/


    /****************************** START OF ARGON2 METHODS ******************************/


    public HashMap<String, String> pbEncrypt(byte[] text, String pass) throws Exception {
        // Generate salt
        SecureRandom randomSalt = new SecureRandom();
        byte[] salt = new byte[32];
        randomSalt.nextBytes(salt);

        // Generating IV.
        int ivSize = 16;
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Hashing pass using Argon2
        byte[] hash = new Argon2.Builder(Version.V13)
                .type(Type.Argon2id)
                .memoryCostKiB(4 * 1024)
                .parallelism(2)
                .iterations(3)
                .hashLength(32)
                .build()
                .hash(pass.getBytes(), salt)
                .getHash();

        SecretKeySpec secretKeySpec = new SecretKeySpec(hash, "AES");

        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(text);

        // Combine IV and encrypted part.
        byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
        System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);

        HashMap<String, String> map = new HashMap<>();
        map.put("salt", Base64.encodeBytes(salt));
        map.put("cipher", Base64.encodeBytes(encryptedIVAndText));

        return map;
    }

    public byte[] pbDecrypt(String encryptedIvText, String salt, String pass) throws Exception {
        int ivSize = 16;
        byte[] encryptedIvTextBytes = Base64.decode(encryptedIvText);

        // Extract IV.
        byte[] iv = new byte[ivSize];
        System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Extract encrypted part.
        int encryptedSize = encryptedIvTextBytes.length - ivSize;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, ivSize, encryptedBytes, 0, encryptedSize);

        // Hash pass using Argon2
        byte[] hash = new Argon2.Builder(Version.V13)
                .type(Type.Argon2id)
                .memoryCostKiB(4 * 1024)
                .parallelism(2)
                .iterations(3)
                .hashLength(32)
                .build()
                .hash(pass.getBytes(), Base64.decode(salt))
                .getHash();

        SecretKeySpec secretKeySpec = new SecretKeySpec(hash, "AES");

        // Decrypt.
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipherDecrypt.doFinal(encryptedBytes);
    }


    /****************************** END OF ARGON2 METHODS ******************************/

    /****************************** START OF FILE ENCRYPTION METHODS ******************************/


    public HashMap<String, String> encryptMedia(String filePath, String contentType) {
        try {
            File file = new File(filePath);
            InputStream is = new FileInputStream(file);

            CipherFileStream cipherFileStream = CipherFile.newStreamBuilder()
                    .withStream(is)
                    .withLength(is.available()).build();

            byte[] fileKey = Util.getSecretBytes(64);
            byte[] fileIV = Util.getSecretBytes(16);
            InputStream dataStream = new PaddingInputStream(cipherFileStream.getInputStream(), cipherFileStream.getLength());

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            String encryptedFilePath = path + "/" + UUID.randomUUID().toString();
            File encryptedFile = new File(encryptedFilePath);
            DigestingOutputStream outputStream = new CipherOutputStreamFactory(fileKey, fileIV).createFor(byteArrayOutputStream);
            byte[] buffer = new byte[4096];
            int read;
            while ((read = dataStream.read(buffer, 0, buffer.length)) != -1) {
                outputStream.write(buffer, 0, read);
            }

            byteArrayOutputStream.flush();
            byteArrayOutputStream.close();
            outputStream.flush();
            outputStream.close();


            FileOutputStream fos = new FileOutputStream(encryptedFile);
            fos.write(byteArrayOutputStream.toByteArray());
            fos.flush();
            fos.close();

            byte[] digest = outputStream.getTransmittedDigest();
            String secret = Base64.encodeBytes(fileKey) + Base64.encodeBytes(digest);
            HashMap<String, String> map = new HashMap<>();
            map.put("uri", "file://" + encryptedFilePath);
            map.put("secret", secret);
            return map;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }


    public String decryptMedia(String filePath, String secret, String outputPath) {
        File file = new File(filePath);
        try {
            String key = secret.substring(0, 88);
            String digest = secret.substring(88);
            InputStream inputStream = CipherInputStream.createForFile(file, file.length(), Base64.decode(key), Base64.decode(digest));
            File outputFile = new File(outputPath);
            byte[] buffer = new byte[8192];
            int read;
            long total = 0;
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            while ((read = inputStream.read(buffer, 0, buffer.length)) != -1) {
                byteArrayOutputStream.write(buffer, 0, read);
                total += read;
            }
            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
            fileOutputStream.write(byteArrayOutputStream.toByteArray());
            fileOutputStream.flush();
            fileOutputStream.close();
            byteArrayOutputStream.flush();
            byteArrayOutputStream.close();
            return "file://" + outputPath;
        } catch (IOException | InvalidMessageException e) {
            e.printStackTrace();
        }
        return null;
    }

    /****************************** END OF FILE ENCRYPTION METHODS ******************************/

    /************************** START OF PAIRWISE SESSION SPECIFIC METHODS ***************************/

    /***
     *
     */
    public JSONObject encryptFilePairwise(String userId, String filePath, String contentMedia) throws JSONException {
        HashMap<String, String> hashMap = encryptMedia(filePath, contentMedia);
        String cipherText = encryptTextPairwise(userId, hashMap.get("secret"));
        JSONObject map = new JSONObject();
        map.put("uri", hashMap.get("uri"));
        map.put("cipher", cipherText);
        return map;
    }

    public String decryptFilePairwise(String senderId, String filePath, String cipher, String outputPath) {
        String secret = decryptTextPairwise(senderId, false, cipher);
        String path = null;
        if (secret != null)
            path = decryptMedia(filePath, secret, outputPath);
        return path;
    }

    /***
     * This method is used to check if a pairwise session exists. Usually would be needed to check the
     * pairwise session for a oneTimeId.
     *
     * @param oneTimeId - String
     * @return boolean
     */
    public boolean pairwiseSessionExists(String oneTimeId) {
        SignalProtocolStore store = new MyProtocolStore(context);
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(oneTimeId, 0);
        return store.containsSession(signalProtocolAddress);
    }

    /************************** END OF PAIRWISE SESSION SPECIFIC METHODS ***************************/

    /****************************** START OF UTILITY METHODS ******************************/

    public String recoverPassword(String userId) {
        HashMap<String, String> serviceMap = new HashMap();
        serviceMap.put("service", passwordKey);
        return keychain.getGenericPassword(userId, serviceMap);
    }

    public void resetDatabase() {
        DatabaseFactory.getInstance(context).resetDatabase(context);
    }

    public boolean isInitialized() {
        SignalProtocolStore store = new MyProtocolStore(context);
        int localId = store.getLocalRegistrationId();
        return localId != 0;
    }


    public void cacheUri(String id, String uri) {
        DatabaseFactory.getFileDatabase(context).insertUri(id, uri);
    }

    public String getUri(String id) {
        String uri = DatabaseFactory.getFileDatabase(context).getUri(id);
        return uri;
    }

    public static synchronized @NonNull
    LiveRecipientCache getRecipientCache() {
        if (recipientCache == null) {
            recipientCache = new LiveRecipientCache(context);
        }
        return recipientCache;
    }

    /****************************** END OF UTILITY METHODS ******************************/

}