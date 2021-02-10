/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

package com.stiiick.stickprotocol.main;

import java.util.HashMap;

/**
 * @author Omar Basem
 */

public interface StickProtocolHandler {

    /*
        This method should be called before uploading any data that needs to be end-to-end encrypted
        to find the right stickId.
     */
    HashMap<String, Object> getStickId(Object... args);

    boolean fetchStickyKey(Object... args);

    void uploadStickyKeys(Object... args);

    void checkPairwiseSession(Object... args);
    
    void decryptGroups(Object... args);

    void decryptProfile(Object... args);

    void decryptFeedData(Object... args);

}
