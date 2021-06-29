/*
 *  Copyright © 2018-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.cipherstream;

import java.io.IOException;
import java.io.OutputStream;

public interface OutputStreamFactory {

    DigestingOutputStream createFor(OutputStream wrap) throws IOException;

}
