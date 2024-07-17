/*
 *  Copyright © 2018-2022 Sticknet.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.recipient;

import android.annotation.SuppressLint;
import android.content.Context;

import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;
import androidx.lifecycle.MutableLiveData;

import com.stiiick.stickprotocol.util.LRUCache;
import com.stiiick.stickprotocol.util.SignalExecutors;

import java.util.Map;

public final class LiveRecipientCache {


    private static final int CACHE_MAX      = 1000;

    private final Context                         context;
    private final Map<RecipientId, LiveRecipient> recipients;
    private final LiveRecipient                   unknown;


    @SuppressLint("UseSparseArrays")
    public LiveRecipientCache(@NonNull Context context) {
        this.context           = context.getApplicationContext();
        this.recipients        = new LRUCache<>(CACHE_MAX);
        this.unknown           = new LiveRecipient(context, new MutableLiveData<>(), Recipient.UNKNOWN);
    }

    @AnyThread
    synchronized @NonNull LiveRecipient getLive(@NonNull RecipientId id) {
        if (id.isUnknown()) return unknown;

        LiveRecipient live = recipients.get(id);

        if (live == null) {
            final LiveRecipient newLive = new LiveRecipient(context, new MutableLiveData<>(), new Recipient(id));

            recipients.put(id, newLive);

            SignalExecutors.BOUNDED.execute(() -> {
                try {
                    newLive.resolve();
                } catch (Error e) {
                    e.printStackTrace();
                }
            });

            live = newLive;
        }

        return live;
    }

}

