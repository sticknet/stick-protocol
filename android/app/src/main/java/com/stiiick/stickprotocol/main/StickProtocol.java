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
import com.stiiick.stickprotocol.keychain.Keychain;
import com.stiiick.stickprotocol.recipient.LiveRecipientCache;
import com.stiiick.stickprotocol.store.MySenderKeyStore;
import com.stiiick.stickprotocol.store.MySignalProtocolStore;
import com.stiiick.stickprotocol.util.Base64;
import com.stiiick.stickprotocol.util.IdentityKeyUtil;
import com.stiiick.stickprotocol.util.Log;
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

/*
    @author Omar Basem
 */

public class StickProtocol {
    private static Context context;
    private static String path;
    private static LiveRecipientCache recipientCache;
    private final Keychain keychain;


    public StickProtocol(Context context) {
        StickProtocol.context = context;
        path = context.getFilesDir().getPath();
        keychain = new Keychain(context);
    }

    public JSONObject refreshSignedPreKey(int days) throws Exception {
//        long signedPreKeyAge = TimeUnit.DAYS.toMillis(30);
        long signedPreKeyAge = TimeUnit.MINUTES.toMillis(2);
        long activeDuration = System.currentTimeMillis() - Preferences.getActiveSignedPreKeyTimestamp(context);
        if (activeDuration > signedPreKeyAge) {
            IdentityKeyPair identityKey = IdentityKeyUtil.getIdentityKeyPair(context);
            SignedPreKeyRecord signedPreKey = PreKeyUtil.generateSignedPreKey(context, identityKey, true);

            HashMap<String, String> serviceMap = new HashMap();
            serviceMap.put("service", "com.stiiick.auth_token");
            String password = keychain.getGenericPassword("com.stiiick", serviceMap);
            JSONObject signedPreKeyJson = new JSONObject();
            signedPreKeyJson.put("id", Preferences.getActiveSignedPreKeyId(context));
            signedPreKeyJson.put("public", Base64.encodeBytes(signedPreKey.getKeyPair().getPublicKey().serialize()));
            signedPreKeyJson.put("signature", Base64.encodeBytes(signedPreKey.getSignature()));
            HashMap<String, String> signedCipherMap = pbEncrypt(signedPreKey.getKeyPair().getPrivateKey().serialize(), password);
            signedPreKeyJson.put("cipher", signedCipherMap.get("cipher"));
            signedPreKeyJson.put("salt", signedCipherMap.get("salt"));
            return signedPreKeyJson;
        }
        return null;
    }

    public void resetDatabase() {
        DatabaseFactory.getInstance(context).resetDatabase(context);
    }


    public void reInit(JSONObject bundle, String password, String oneTimeId, ProgressEvent progressEvent) {
        //  ** Regenerate previous keys  ** //
        try {
            // Store password in BlockStore/KeyStore
            HashMap<String, String> serviceMap = new HashMap();
            serviceMap.put("service", context.getPackageName());
            keychain.setGenericPassword(context.getPackageName(), "password", password, serviceMap);

            IdentityKey publicKey = new IdentityKey(Base64.decode((String) bundle.get("identityPublic")), 0);
            byte[] identityCipher = pbDecrypt((String) bundle.get("identityCipher"), (String) bundle.get("identitySalt"), password);
            ECPrivateKey privateKey = Curve.decodePrivatePoint(identityCipher);
            IdentityKeyPair identityKeyPair = new IdentityKeyPair(publicKey, privateKey);
            IdentityKeyUtil.save(context, "pref_identity_public_v3", Base64.encodeBytes(publicKey.serialize()));
            IdentityKeyUtil.save(context, "pref_identity_private_v3", Base64.encodeBytes(privateKey.serialize()));
            SignalProtocolStore store = new MySignalProtocolStore(context);

            JSONArray preKeys = (JSONArray) bundle.get("preKeys");
            JSONArray senderKeys = (JSONArray) bundle.get("senderKeys");
            JSONArray signedPreKeys = (JSONArray) bundle.get("signedPreKeys");
            int totalKeys = signedPreKeys.length() + preKeys.length() + senderKeys.length();

            for (int i = 0; i < signedPreKeys.length(); i++) {
                JSONObject SPKJson = signedPreKeys.getJSONObject(i);
                ECPublicKey sigPublicKey = Curve.decodePoint(Base64.decode((String) SPKJson.getString("public")), 0);
                byte[] signedCipher = pbDecrypt((String) SPKJson.getString("cipher"), (String) SPKJson.getString("salt"), password);
                ECPrivateKey sigPrivateKey = Curve.decodePrivatePoint(signedCipher);
                ECKeyPair sigKeyPair = new ECKeyPair(sigPublicKey, sigPrivateKey);
                int signedPreKeId = (int) SPKJson.get("id");
                SignedPreKeyRecord record = new SignedPreKeyRecord(signedPreKeId, System.currentTimeMillis(), sigKeyPair, Base64.decode(SPKJson.getString("signature")));
                store.storeSignedPreKey(signedPreKeId, record);
                if (SPKJson.getBoolean("active")) {
                    Log.d("SETTING ACTIVE SPKXXX", Long.toString(SPKJson.getLong("timestamp")));
                    Preferences.setActiveSignedPreKeyId(context, signedPreKeId);
                    Preferences.setActiveSignedPreKeyTimestamp(context, SPKJson.getLong("timestamp"));
                }

                // PROGRESS
                if (progressEvent != null) {
                    JSONObject event = new JSONObject();
                    event.put("progress", i + 1);
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
                if (progressEvent != null) {
                    JSONObject event = new JSONObject();
                    event.put("progress", signedPreKeys.length() + i + 1);
                    event.put("total", totalKeys);
                    progressEvent.execute(event);
                }
            }

            // KEYS FOR SENDING SELF
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress((String) bundle.get("userId"), 1);
            for (int i = 0; i < senderKeys.length(); i++) {
                JSONObject senderKeyJson = senderKeys.getJSONObject(i);
                reinitSenderKey(senderKeyJson, signalProtocolAddress, (String) bundle.get("userId"));
                // PROGRESS
                if (progressEvent != null) {
                    JSONObject event = new JSONObject();
                    event.put("progress", signedPreKeys.length() + preKeys.length() + i + 1);
                    event.put("total", totalKeys);
                    progressEvent.execute(event);
                }
            }
            PreferenceManager.getDefaultSharedPreferences(context).edit().putString("oneTimeId", oneTimeId).apply();
            PreferenceManager.getDefaultSharedPreferences(context).edit().putString("userId", (String) bundle.get("userId")).apply();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // *** //
    }

    public void reinitSenderKey(JSONObject senderKey, SignalProtocolAddress signalProtocolAddress, String userId) throws IOException, InvalidKeyException, NoSessionException, JSONException {
        SenderKeyName senderKeyName = new SenderKeyName(senderKey.getString("stickId"), signalProtocolAddress);
        SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
        SenderKeyRecord senderKeyRecord = senderKeyStore.loadSenderKey(senderKeyName);
        ECPublicKey senderPubKey = Curve.decodePoint(Base64.decode(senderKey.getString("public")), 0);
        String cipher = decryptTextPairwise(userId, 1, true, senderKey.getString("cipher"));
        ECPrivateKey senderPrivKey = Curve.decodePrivatePoint(Base64.decode(cipher));
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


    public void ratchetChain(String stickId, int steps) throws NoSessionException {
        String userId = PreferenceManager.getDefaultSharedPreferences(context).getString("userId", "");
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, 1);
        SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
        SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
        GroupCipher groupCipher = new GroupCipher(senderKeyStore, senderKeyName);
        groupCipher.ratchetChain(steps);
    }

    public JSONArray generatePreKeys(int nextPreKeyId, int count) {
        try {
            HashMap<String, String> serviceMap = new HashMap();
            serviceMap.put("service", "com.stiiick.auth_token");
            String password = keychain.getGenericPassword("com.stiiick", serviceMap);
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

    public interface ProgressEvent {
        void execute(JSONObject event);
    }

    /*
        This method is used to create the initial password hash, from a provided password and salt, at login
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

    public JSONObject initialize(String userId, String password, ProgressEvent progressEvent) {
        try {
            HashMap<String, String> serviceMap = new HashMap();
            serviceMap.put("service", context.getPackageName());
            keychain.setGenericPassword(context.getPackageName(), "password", password, serviceMap);

            // Generate password salt
            SecureRandom randomSalt = new SecureRandom();
            byte[] salt = new byte[32];
            randomSalt.nextBytes(salt);
            // Hashing pass
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

            SignalProtocolStore store = new MySignalProtocolStore(context);
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

            JSONObject identityKeyJson = new JSONObject();
            identityKeyJson.put("public", Base64.encodeBytes(identityKey.getPublicKey().serialize()));
            identityKeyJson.put("localId", KeyHelper.generateRegistrationId(false));
            HashMap<String, String> identityCipherMap = pbEncrypt(identityKey.getPrivateKey().serialize(), password);
            identityKeyJson.put("cipher", identityCipherMap.get("cipher"));
            identityKeyJson.put("salt", identityCipherMap.get("salt"));

            String oneTimeId = UUID.randomUUID().toString();
            JSONObject map = new JSONObject();
            map.put("identityKey", identityKeyJson);
            map.put("signedPreKey", signedPreKeyJson);
            map.put("preKeys", preKeysArray);
            map.put("passwordHash", passwordHash);
            map.put("passwordSalt", Base64.encodeBytes(salt));
            map.put("oneTimeId", oneTimeId);
            PreferenceManager.getDefaultSharedPreferences(context).edit().putString("oneTimeId", oneTimeId).apply();
            PreferenceManager.getDefaultSharedPreferences(context).edit().putString("userId", userId).apply();

            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, 0);
            SessionBuilder sessionBuilder = new SessionBuilder(store, signalProtocolAddress);
            ECPublicKey preKey = Curve.decodePoint(preKeys.get(0).getKeyPair().getPublicKey().serialize(), 0);

            PreKeyBundle preKeyBundle = new PreKeyBundle(
                    store.getLocalRegistrationId(),
                    1,
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

    public boolean isInitialized() {
        SignalProtocolStore store = new MySignalProtocolStore(context);
        int localId = store.getLocalRegistrationId();
        return localId != 0;
    }

    public void initPairwiseSession(JSONObject bundle) {
        try {
            SignalProtocolStore store = new MySignalProtocolStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(bundle.getString("userId"), bundle.getInt("deviceId"));
            SessionBuilder sessionBuilder = new SessionBuilder(store, signalProtocolAddress);
            ECPublicKey preKey = Curve.decodePoint(Base64.decode(bundle.getString("preKey")), 0);
            ECPublicKey signedPreKey = Curve.decodePoint(Base64.decode(bundle.getString("signedPreKey")), 0);
            ECPublicKey identityKey = Curve.decodePoint(Base64.decode(bundle.getString("identityKey")), 0);
            IdentityKey identityPublicKey = new IdentityKey(identityKey);

            PreKeyBundle preKeyBundle = new PreKeyBundle(
                    bundle.getInt("localId"),
                    bundle.getInt("deviceId"),
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

    public boolean pairwiseSessionExists(String oneTimeId) {
        SignalProtocolStore store = new MySignalProtocolStore(context);
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(oneTimeId, 0);
        return store.containsSession(signalProtocolAddress);
    }

    public String encryptTextPairwise(String userId, int deviceId, String text) {
        try {
            SignalProtocolStore store = new MySignalProtocolStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, deviceId);
            SessionCipher sessionCipher = new SessionCipher(store, signalProtocolAddress);
            CiphertextMessage cipher = sessionCipher.encrypt(text.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeBytes(cipher.serialize());
        } catch (UntrustedIdentityException e) {
            e.printStackTrace();
            return null;
        }
    }

    public JSONObject getEncryptingSenderKey(String userId, String stickId, Boolean isSticky) {
        try {
            SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, isSticky ? 1 : 0);
            SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
            GroupSessionBuilder groupSessionBuilder = new GroupSessionBuilder(senderKeyStore);
            SenderKeyDistributionMessage senderKeyDistributionMessage = groupSessionBuilder.create(senderKeyName);
            DatabaseFactory.getStickyKeyDatabase(context).insertStickyKey(stickId, Base64.encodeBytes(senderKeyDistributionMessage.serialize()));
            SenderKeyState senderKeyState = senderKeyStore.loadSenderKey(senderKeyName).getSenderKeyState();
            String cipher = encryptTextPairwise(userId, isSticky ? 1 : 0, Base64.encodeBytes(senderKeyState.getSigningKeyPrivate().serialize()));
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
        return encryptTextPairwise(targetId, isSticky ? 1 : 0, Base64.encodeBytes(senderKeyDistributionMessage.serialize()));
    }


    public int getChainStep(String userId, String stickId) {
        SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, 1);
        SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
        try {
            int step = senderKeyStore.loadSenderKey(senderKeyName).getSenderKeyState().getSenderChainKey().getIteration();
            return step;
        } catch (InvalidKeyIdException e) {
            e.printStackTrace();
            return 9999;
        }
    }

    public String encryptText(String userId, String stickId, String text, Boolean isSticky) {
        try {
            SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, isSticky ? 1 : 0);
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

    public Boolean sessionExists(String senderId, String stickId, Boolean isSticky) {
        SenderKeyStore mySenderKeyStore = new MySenderKeyStore(context);
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, isSticky ? 1 : 0);
        SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
        SenderKeyRecord record = mySenderKeyStore.loadSenderKey(senderKeyName);
        return !record.isEmpty();
    }


    public void reinitMyStickySession(JSONObject senderKey) throws IOException, InvalidKeyException, NoSessionException, JSONException {
        String userId = PreferenceManager.getDefaultSharedPreferences(context).getString("userId", "");
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(userId, 1);
        reinitSenderKey(senderKey, signalProtocolAddress, userId);
    }


    public void initSession(String senderId, String stickId, String cipherSenderKey, Boolean isSticky) {
        try {
            if (cipherSenderKey != null) {
                SenderKeyStore senderKeyStore = new MySenderKeyStore(context);
                SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, isSticky ? 1 : 0);
                SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
                GroupSessionBuilder groupSessionBuilder = new GroupSessionBuilder(senderKeyStore);
                String senderKey = decryptTextPairwise(senderId, isSticky ? 1 : 0, true, cipherSenderKey);
                if (senderKey != null) {
                    SenderKeyDistributionMessage senderKeyDistributionMessage = new SenderKeyDistributionMessage(Base64.decode(senderKey));
                    groupSessionBuilder.process(senderKeyName, senderKeyDistributionMessage);
                }
            }
        } catch (InvalidMessageException | LegacyMessageException | IOException e) {
            e.printStackTrace();
        }
    }

    public String decryptText(String senderId, String stickId, String cipher, Boolean isSticky) {
        if (cipher.length() < 4)
            return null;
        try {
            Boolean isSelf = senderId.equals(PreferenceManager.getDefaultSharedPreferences(context).getString("userId", ""));
            SenderKeyStore mySenderKeyStore = new MySenderKeyStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, isSticky ? 1 : 0);
            SenderKeyName senderKeyName = new SenderKeyName(stickId, signalProtocolAddress);
            GroupCipher groupCipher = new GroupCipher(mySenderKeyStore, senderKeyName);
            byte[] decryptedCipher;
            decryptedCipher = groupCipher.decrypt(Base64.decode(cipher), isSticky, isSelf);
            return new String(decryptedCipher, StandardCharsets.UTF_8);
        } catch (LegacyMessageException | InvalidMessageException | DuplicateMessageException | NoSessionException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void deleteSession(String stickId, String senderId) {
        SenderKeyStore mySenderKeyStore = new MySenderKeyStore(context);
        SignalProtocolAddress signalProtocolAddress0 = new SignalProtocolAddress(senderId, 0);
        SignalProtocolAddress signalProtocolAddress1 = new SignalProtocolAddress(senderId, 1);
        SenderKeyName senderKeyName0 = new SenderKeyName(stickId, signalProtocolAddress0);
        SenderKeyName senderKeyName1 = new SenderKeyName(stickId, signalProtocolAddress1);
        SenderKeyRecord senderKeyRecord = new SenderKeyRecord();
        mySenderKeyStore.storeSenderKey(senderKeyName0, senderKeyRecord);
        mySenderKeyStore.storeSenderKey(senderKeyName1, senderKeyRecord);
    }


    public String decryptTextPairwise(String senderId, int deviceId, boolean isStickyKey, String cipher) {
        try {
            SignalProtocolStore store = new MySignalProtocolStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, deviceId);
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
        } catch (InvalidMessageException | DuplicateMessageException | LegacyMessageException | UntrustedIdentityException | InvalidVersionException | InvalidKeyIdException | InvalidKeyException | NoSessionException | IOException e) {
            e.printStackTrace();
            SignalProtocolStore store = new MySignalProtocolStore(context);
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, deviceId);
            SessionCipher sessionCipher = new SessionCipher(store, signalProtocolAddress);
            byte[] bytes = null;
            try {
                PreKeySignalMessage preKeySignalMessage = new PreKeySignalMessage(Base64.decode(cipher));
                bytes = sessionCipher.decrypt(preKeySignalMessage);
            } catch (DuplicateMessageException | LegacyMessageException | InvalidMessageException | InvalidKeyIdException | InvalidKeyException | UntrustedIdentityException | InvalidVersionException | IOException ex) {
                ex.printStackTrace();
            }
            if (bytes != null)
                return new String(bytes, StandardCharsets.UTF_8);
            else
                return null;
        }
    }

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

    public JSONObject encryptFilePairwise(String userId, String filePath, String contentMedia) throws JSONException {
        HashMap<String, String> hashMap = encryptMedia(filePath, contentMedia);
        String cipherText = encryptTextPairwise(userId, 0, hashMap.get("secret"));
        JSONObject map = new JSONObject();
        map.put("uri", hashMap.get("uri"));
        map.put("cipher", cipherText);
        return map;
    }


    public JSONObject encryptFile(String senderId, String stickId, String filePath, String contentMedia, Boolean isSticky) throws JSONException {
        HashMap<String, String> hashMap = encryptMedia(filePath, contentMedia);
        String cipherText = encryptText(senderId, stickId, hashMap.get("secret"), isSticky);
        JSONObject map = new JSONObject();
        map.put("uri", hashMap.get("uri"));
        map.put("cipher", cipherText);
        return map;

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


    public String decryptFilePairwise(String senderId, String filePath, String cipher, int size, String outputPath) {
        String secret = decryptTextPairwise(senderId, 0, false, cipher);
        String path = null;
        if (secret != null)
            path = decryptMedia(filePath, secret, outputPath);
        return path;
    }

    public String decryptFile(String senderId, String stickId, String filePath, String cipher, int size, String outputPath, Boolean isSticky) {
        String secret = decryptText(senderId, stickId, cipher, isSticky);
        String path = null;
        if (secret != null)
            path = decryptMedia(filePath, secret, outputPath);
        return path;
    }

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

        // Hashing pass
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

        // Hash pass
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
}