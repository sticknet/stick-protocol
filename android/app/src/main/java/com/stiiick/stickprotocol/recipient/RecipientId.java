/*
 *  Copyright (c) 2018-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.recipient;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;


public class RecipientId implements Parcelable, Comparable<RecipientId> {

    private static final long UNKNOWN_ID = -1;

    public static final RecipientId UNKNOWN = RecipientId.from(UNKNOWN_ID);

    private final long id;

    public static RecipientId from(long id) {
        if (id == 0) {
            throw new InvalidLongRecipientIdError();
        }

        return new RecipientId(id);
    }

    public static RecipientId from(@NonNull String id) {
        try {
            return RecipientId.from(Long.parseLong(id));
        } catch (NumberFormatException e) {
            throw new InvalidStringRecipientIdError();
        }
    }

    private RecipientId(long id) {
        this.id = id;
    }

    private RecipientId(Parcel in) {
        id = in.readLong();
    }

    public boolean isUnknown() {
        return id == UNKNOWN_ID;
    }

    public @NonNull String serialize() {
        return String.valueOf(id);
    }

    @Override
    public @NonNull String toString() {
        return "RecipientId::" + id;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        RecipientId that = (RecipientId) o;

        return id == that.id;
    }

    @Override
    public int hashCode() {
        return (int) (id ^ (id >>> 32));
    }

    @Override
    public int compareTo(RecipientId o) {
        return Long.compare(this.id, o.id);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeLong(id);
    }

    public static final Creator<RecipientId> CREATOR = new Creator<RecipientId>() {
        @Override
        public RecipientId createFromParcel(Parcel in) {
            return new RecipientId(in);
        }

        @Override
        public RecipientId[] newArray(int size) {
            return new RecipientId[size];
        }
    };

    private static class InvalidLongRecipientIdError extends AssertionError {}
    private static class InvalidStringRecipientIdError extends AssertionError {}
}
