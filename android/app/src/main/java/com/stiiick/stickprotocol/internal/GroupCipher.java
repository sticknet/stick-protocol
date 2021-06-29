/*
 *  Copyright © 2018-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.internal;

import org.whispersystems.libsignal.DecryptionCallback;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.groups.ratchet.SenderChainKey;
import org.whispersystems.libsignal.groups.ratchet.SenderMessageKey;
import org.whispersystems.libsignal.groups.state.SenderKeyRecord;
import org.whispersystems.libsignal.groups.state.SenderKeyState;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.groups.SenderKeyName;
import org.whispersystems.libsignal.logging.Log;
import org.whispersystems.libsignal.protocol.SenderKeyMessage;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * @author Omar Basem
 */


public class GroupCipher {

    static final Object LOCK = new Object();

    private final SenderKeyStore senderKeyStore;
    private final SenderKeyName senderKeyId;

    public GroupCipher(SenderKeyStore senderKeyStore, SenderKeyName senderKeyId) {
        this.senderKeyStore = senderKeyStore;
        this.senderKeyId = senderKeyId;
    }

    /**
     * Encrypt a message.
     *
     * @param paddedPlaintext The plaintext message bytes, optionally padded.
     * @return Ciphertext.
     * @throws NoSessionException
     */


    /**
     * Decrypt a SenderKey group message.
     *
     * @return Plaintext
     * @throws LegacyMessageException
     * @throws InvalidMessageException
     * @throws DuplicateMessageException
     */


    private byte[] getPlainText(byte[] iv, byte[] key, byte[] ciphertext)
            throws InvalidMessageException {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);
            return cipher.doFinal(ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException |
                InvalidAlgorithmParameterException e) {
            throw new AssertionError(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidMessageException(e);
        }
    }

    private byte[] getCipherText(byte[] iv, byte[] key, byte[] plaintext) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);
            return cipher.doFinal(plaintext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                IllegalBlockSizeException | BadPaddingException | java.security.InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    private static class NullDecryptionCallback implements DecryptionCallback {
        @Override
        public void handlePlaintext(byte[] plaintext) {
        }
    }

    public void ratchetChain(int steps) throws NoSessionException {
        synchronized (LOCK) {
            try {
                SenderKeyRecord record = senderKeyStore.loadSenderKey(senderKeyId);
                SenderKeyState senderKeyState = record.getSenderKeyState();
                for (int i = 0; i < steps; i++) {
                    senderKeyState.addSenderMessageKey(senderKeyState.getSenderChainKey().getSenderMessageKey());
                    senderKeyState.setSenderChainKey(senderKeyState.getSenderChainKey().getNext());
                }
                senderKeyStore.storeSenderKey(senderKeyId, record);
            } catch (InvalidKeyIdException e) {
                throw new NoSessionException(e);
            }
        }
    }

    public byte[] encrypt(byte[] paddedPlaintext, Boolean isSticky) throws NoSessionException, DuplicateMessageException, InvalidMessageException {
        synchronized (LOCK) {
            try {
                SenderKeyRecord record = senderKeyStore.loadSenderKey(senderKeyId);
                SenderKeyState senderKeyState = record.getSenderKeyState();
                SenderMessageKey senderKey = senderKeyState.getSenderChainKey().getSenderMessageKey();
                byte[] ciphertext = getCipherText(senderKey.getIv(), senderKey.getCipherKey(), paddedPlaintext);

                SenderKeyMessage senderKeyMessage = new SenderKeyMessage(senderKeyState.getKeyId(),
                        senderKey.getIteration(),
                        ciphertext,
                        senderKeyState.getSigningKeyPrivate());

                if (isSticky)
                    senderKeyState.addSenderMessageKey(senderKey);
                senderKeyState.setSenderChainKey(senderKeyState.getSenderChainKey().getNext());

                senderKeyStore.storeSenderKey(senderKeyId, record);

                return senderKeyMessage.serialize();
            } catch (InvalidKeyIdException e) {
                throw new NoSessionException(e);
            }
        }
    }

    public byte[] decrypt(byte[] senderKeyMessageBytes, Boolean isSticky, Boolean isSelf)
            throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException {
        return decrypt(senderKeyMessageBytes, new NullDecryptionCallback(), isSticky, isSelf);
    }


    public byte[] decrypt(byte[] senderKeyMessageBytes, DecryptionCallback callback, Boolean isSticky, Boolean isSelf)
            throws LegacyMessageException, InvalidMessageException, DuplicateMessageException,
            NoSessionException {
        synchronized (LOCK) {
            try {
                SenderKeyRecord record = senderKeyStore.loadSenderKey(senderKeyId);

                if (record.isEmpty()) {
                    throw new NoSessionException("No sender key for: " + senderKeyId);
                }

                SenderKeyMessage senderKeyMessage = new SenderKeyMessage(senderKeyMessageBytes);
                SenderKeyState senderKeyState = record.getSenderKeyState(senderKeyMessage.getKeyId());

                senderKeyMessage.verifySignature(senderKeyState.getSigningKeyPublic());

                SenderMessageKey senderKey = getSenderKey(senderKeyState, senderKeyMessage.getIteration(), isSticky);

                byte[] plaintext = getPlainText(senderKey.getIv(), senderKey.getCipherKey(), senderKeyMessage.getCipherText());

                callback.handlePlaintext(plaintext);

                if (!isSelf)
                    senderKeyStore.storeSenderKey(senderKeyId, record);

                return plaintext;
            } catch (org.whispersystems.libsignal.InvalidKeyException | InvalidKeyIdException e) {
                throw new InvalidMessageException(e);
            }
        }
    }

    private SenderMessageKey getSenderKey(SenderKeyState senderKeyState, int iteration, Boolean isSticky)
            throws DuplicateMessageException, InvalidMessageException {
        SenderChainKey senderChainKey = senderKeyState.getSenderChainKey();

        if (senderChainKey.getIteration() > iteration) {
            if (senderKeyState.hasSenderMessageKey(iteration)) {
                return senderKeyState.removeSenderMessageKey(iteration, isSticky);
            } else {
                throw new DuplicateMessageException("Received message with old counter: " +
                        senderChainKey.getIteration() + " , " + iteration);
            }
        }

        if (iteration - senderChainKey.getIteration() > 2000) {
            throw new InvalidMessageException("Over 2000 messages into the future!");
        }
        while (senderChainKey.getIteration() < iteration) {
            if (!isSticky)
                senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey());
            senderChainKey = senderChainKey.getNext();
        }

        if (!isSticky)
            senderKeyState.setSenderChainKey(senderChainKey.getNext());

        return senderChainKey.getSenderMessageKey();
    }
}
