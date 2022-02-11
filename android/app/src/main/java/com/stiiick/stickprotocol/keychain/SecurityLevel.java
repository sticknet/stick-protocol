/*
 *  Copyright © 2018-2022 Stick.
 *  
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.keychain;

import androidx.annotation.NonNull;

/** Minimal required level of the security implementation. */
public enum SecurityLevel {
  /** No security guarantees needed (default value); Credentials can be stored in FB Secure Storage */
  ANY,
  /** Requires for the key to be stored in the Android Keystore, separate from the encrypted data. */
  SECURE_SOFTWARE,
  /** Requires for the key to be stored on a secure hardware (Trusted Execution Environment or Secure Environment). */
  SECURE_HARDWARE;

  /** Get JavaScript friendly name. */
  @NonNull
  public String jsName() {
    return String.format("SECURITY_LEVEL_%s", this.name());
  }

  public boolean satisfiesSafetyThreshold(@NonNull final SecurityLevel threshold) {
    return this.compareTo(threshold) >= 0;
  }
}

