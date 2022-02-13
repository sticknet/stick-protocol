/*
 *  Copyright © 2018-2022 StickNet.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.util;


import androidx.annotation.NonNull;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public class SignalExecutors {

    public static final ExecutorService BOUNDED   = Executors.newFixedThreadPool(Math.max(2, Math.min(Runtime.getRuntime().availableProcessors() - 1, 4)), new NumberedThreadFactory("signal-bounded"));

    private static class NumberedThreadFactory implements ThreadFactory {

        private final String        baseName;
        private final AtomicInteger counter;

        NumberedThreadFactory(@NonNull String baseName) {
            this.baseName = baseName;
            this.counter  = new AtomicInteger();
        }

        @Override
        public Thread newThread(@NonNull Runnable r) {
            return new Thread(r, baseName + "-" + counter.getAndIncrement());
        }
    }
}
