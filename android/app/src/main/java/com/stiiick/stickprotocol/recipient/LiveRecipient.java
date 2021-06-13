/*
 *  Copyright (c) 2018-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.recipient;


import android.content.Context;

import androidx.annotation.NonNull;
import androidx.annotation.WorkerThread;
import androidx.lifecycle.MutableLiveData;

import com.annimon.stream.Stream;
import com.stiiick.stickprotocol.database.DatabaseFactory;
import com.stiiick.stickprotocol.database.RecipientDatabase;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public final class LiveRecipient {


    private final Context                       context;
    private final MutableLiveData<Recipient>    liveData;
    private final AtomicReference<Recipient>    recipient;
    private final RecipientDatabase recipientDatabase;

    LiveRecipient(@NonNull Context context, @NonNull MutableLiveData<Recipient> liveData, @NonNull Recipient defaultRecipient) {
        this.context           = context.getApplicationContext();
        this.liveData          = liveData;
        this.recipient         = new AtomicReference<>(defaultRecipient);
        this.recipientDatabase = DatabaseFactory.getRecipientDatabase(context);
    }

    public @NonNull RecipientId getId() {
        return recipient.get().getId();
    }

    /**
     * @return A recipient that may or may not be fully-resolved.
     */
    public @NonNull Recipient get() {
        return recipient.get();
    }


    /**
     * @return A fully-resolved version of the recipient. May require reading from disk.
     */
    @WorkerThread
    public @NonNull Recipient resolve() {
        Recipient current = recipient.get();

        if (!current.isResolving() || current.getId().isUnknown()) {
            return current;
        }


        Recipient       updated      = fetchRecipientFromDisk(getId());
        List<Recipient> participants = Stream.of(updated.getParticipants())
                .filter(Recipient::isResolving)
                .map(Recipient::getId)
                .map(this::fetchRecipientFromDisk)
                .toList();

        for (Recipient participant : participants) {
            participant.live().set(participant);
        }

        set(updated);

        return updated;
    }



    private @NonNull Recipient fetchRecipientFromDisk(RecipientId id) {
        return new Recipient(id);
    }

    private synchronized void set(@NonNull Recipient recipient) {
        this.recipient.set(recipient);
        this.liveData.postValue(recipient);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LiveRecipient that = (LiveRecipient) o;
        return recipient.equals(that.recipient);
    }

    @Override
    public int hashCode() {
        return Objects.hash(recipient);
    }
}
