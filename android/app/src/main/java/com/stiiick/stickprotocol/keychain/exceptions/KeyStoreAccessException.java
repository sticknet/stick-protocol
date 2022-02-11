/*
 *  Copyright © 2018-2022 Stick.
 *  
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.keychain.exceptions;

import java.security.GeneralSecurityException;

public class KeyStoreAccessException extends GeneralSecurityException {
  public KeyStoreAccessException(final String message) {
    super(message);
  }

  public KeyStoreAccessException(final String message, final Throwable t) {
    super(message, t);
  }
}
