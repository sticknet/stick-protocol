/*
 *  Copyright © 2018-2022 Stick.
 *  
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.keychain.exceptions;

import androidx.annotation.Nullable;

import java.security.GeneralSecurityException;

public class CryptoFailedException extends GeneralSecurityException {
  public CryptoFailedException(String message) {
    super(message);
  }

  public CryptoFailedException(String message, Throwable t) {
    super(message, t);
  }

  public static void reThrowOnError(@Nullable final Throwable error) throws CryptoFailedException {
    if(null == error) return;

    if (error instanceof CryptoFailedException)
      throw (CryptoFailedException) error;

    throw new CryptoFailedException("Wrapped error: " + error.getMessage(), error);

  }
}
