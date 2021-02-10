/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.recipient;


import android.content.Context;

import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;
import androidx.annotation.WorkerThread;

import com.stiiick.stickprotocol.database.DatabaseFactory;
import com.stiiick.stickprotocol.database.RecipientDatabase;
import com.stiiick.stickprotocol.main.StickProtocol;
import com.stiiick.stickprotocol.util.UuidUtil;

import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.libsignal.util.guava.Preconditions;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;


public class Recipient {

    public static final Recipient UNKNOWN = new Recipient(RecipientId.UNKNOWN);
    private final RecipientId            id;
    private final boolean                resolving;
    private final List<Recipient>        participants;

    private final UUID                   uuid;

    /**
     * Returns a {@link LiveRecipient}, which contains a {@link Recipient} that may or may not be
     * populated with data. However, you can observe the value that's returned to be notified when the
     * {@link Recipient} changes.
     */
    @AnyThread
    public static @NonNull LiveRecipient live(@NonNull RecipientId id) {
        Preconditions.checkNotNull(id, "ID cannot be null.");
        return StickProtocol.getRecipientCache().getLive(id);
    }

    public @NonNull LiveRecipient live() {
        return StickProtocol.getRecipientCache().getLive(id);
    }

    /**
     * Returns a fully-populated {@link Recipient}. May hit the disk, and therefore should be
     * called on a background thread.
     */
    @WorkerThread
    public static @NonNull Recipient resolved(@NonNull RecipientId id) {
        Preconditions.checkNotNull(id, "ID cannot be null.");
        return live(id).resolve();
    }

    /**
     * Returns a fully-populated {@link Recipient} based off of a string identifier, creating one in
     * the database if necessary. The identifier may be a uuid, phone number, email,
     * or serialized groupId.
     *
     * If the identifier is a UUID of a Signal user, prefer using
     * {@link #(Context, UUID, String)} or its overload, as this will let us associate
     * the phone number with the recipient.
     */
    @WorkerThread
    public static @NonNull Recipient external(@NonNull Context context, @NonNull String identifier) {
        Preconditions.checkNotNull(identifier, "Identifier cannot be null!");

        RecipientDatabase db = DatabaseFactory.getRecipientDatabase(context);
        RecipientId       id = null;

        if (UuidUtil.isUuid(identifier)) {
            UUID uuid = UuidUtil.parseOrThrow(identifier);

            id = db.getOrInsertFromUuid(uuid);
        }

        return Recipient.resolved(id);
    }

    /**
     * @return A string identifier able to be used with the Signal service. Prefers UUID, and if not
     * available, will return an E164 number.
     */
    public @NonNull String requireServiceId() {
        Recipient resolved = resolving ? resolve() : this;
        return resolved.getUuid().get().toString();
    }

    public @NonNull
    Optional<UUID> getUuid() {
        return Optional.fromNullable(uuid);
    }


    /**
     * If this recipient is missing crucial data, this will return a populated copy. Otherwise it
     * returns itself.
     */
    public @NonNull Recipient resolve() {
        if (resolving) {
            return live().resolve();
        } else {
            return this;
        }
    }

    Recipient(@NonNull RecipientId id) {
        this.id                     = id;
        this.resolving              = true;
        this.uuid                   = null;
        this.participants           = Collections.emptyList();
    }

    public @NonNull RecipientId getId() {
        return id;
    }

    public boolean isResolving() {
        return resolving;
    }

    public @NonNull List<Recipient> getParticipants() {
        return new ArrayList<>(participants);
    }


    @Override
    public int hashCode() {
        return Objects.hash(id);
    }



}
