/*
 *  Copyright (c) 2020-2021 STiiiCK.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

import axios from "axios"; // To make HTTP requests

/**
 *  This class contains common handler methods needed for the StickProtocol client-side. These handlers may differ
 *  from one application to another. So, you are free to write your own handlers. These handlers can be implemented
 *  using Java/Kotlin/Swift/Objective-C or any other programming language. This file is an example implementation of
 *  the StickProtocolHandlers in Javascript.
 *
 *  @author Omar Basem
 */

export default class StickProtocolHandlers {

    constructor(StickProtocol, data) {
        this.StickProtocol = StickProtocol
        this.userId = data.userId
        this.userOneTimeId = data.userOneTimeId
        this.URL = data.URL
        this.token = data.token
        this.httpConfig = {headers: {"Authorization": data.token}}
        this.isDev = data.isDev
    }

    /**
     * This method should be called before uploading any data that needs to be end-to-end encrypted
     * to get the right stickId from the server.
     *
     * args:
     *  - groups: a list groups or groupsIds to share to
     *  - connections: a list of users or usersIds to share to
     *  - isProfile: boolean indicating whether the user is sharing to their profile (i.e: with all their connections)
     *  - type: an enum, {`group`: encrypting to a single group, `multi`: encrypting to multiple targets,
     *  `self`: encrypting to currentUser only}
     *  - providedPartyId (optional): id of the `Party` which the data needs to be e2e encrypted to.
     */
    async getStickId(groups, connections, isProfile, type, providedPartyId = null) {
        const userId = this.userId
        let groups_ids = [], connections_ids = [];

        if (type === 'multi') { // encrypting to multiple groups and/or users
            if (!isProfile) {
                for (let i = 0; i < groups.length; i++) {
                    groups_ids.push(groups[i].id || groups[i])
                }
                for (let i = 0; i < connections.length; i++) {
                    connections_ids.push(connections[i].id || connections[i])
                }
            } else { // encrypting to all of a user's connections
                connections_ids = connections
                connections_ids.push(userId)
            }
        } else if (type === 'group') { // encrypting to a single group
            groups_ids = [groups[0].id]
        } else if (type === 'self') // encrypting to self (currentUser) only
            connections_ids = [userId]

        connections_ids = connections_ids.filter(id => id !== null) // make sure no id is null

        // make a request to the server to get the stickId, and which users does not yet have the sender keys
        // corresponding to that stickId
        let body = {
            groups_ids,
            connections_ids,
            isSticky: true,
            isProfile
        }
        if (providedPartyId)
            body.partyId = providedPartyId
        let partyId, stickId;
        const res = await axios.post(`${this.URL}/api/fetch-uploaded-sks/`, body, this.httpConfig)
        stickId = res.data.stickId
        partyId = res.data.partyId
        let users_id = res.data.bundlesToFetch
        if (users_id.length > 0) {
            // upload sender keys to users that do not have them yet
            await this.uploadSenderKeys(stickId, users_id)
        }

        // Update the chain step of the corresponding sticky session if needed
        await this.syncChain(res.data.step, stickId)

        return {partyId, stickId, groups_ids, connections_ids}
    }

    /**
     * This function is used to upload sender keys of a sticky session to server. StickProtocol.getSenderKey() will return
     * a DecryptingSenderKey for other members of a party, while StickProtocol.getEncryptingSenderKey() will return a
     * user's own EncryptingSenderKey for a sticky session.
     *
     */
    async uploadSenderKeys(stickId, users_id = null, group_id = null) {
        // Fetch preKey bundles of users to create new pairwise sessions and encrypt to them the sender keys

        // you can either provide a list of users_id, or a group_id which will correspond to all the members of that group
        const data = users_id ? {users_id} : {group_id};
        const bundlesRes = await axios.post(`${this.URL}/api/fetch-pkbs/`, data, this.httpConfig)
        const {bundles} = bundlesRes.data
        users_id = bundlesRes.data.users_id
        const keys = {};

        // loop over the users list returned from the server and encrypt to each of them the sender key
        for (let i = 0; i < users_id.length; i++) {
            const memberId = users_id[i];
            await this.StickProtocol.initPairwiseSession(bundles[memberId])
            const preKeyId = bundles[memberId].preKeyId
            const identityKeyId = bundles[memberId].identityKeyId
            if (memberId !== this.userId) {
                const key = await this.StickProtocol.getSenderKey(this.userId, memberId, stickId, true);
                keys[memberId] = {identityKeyId, preKeyId, key, stickId, forUser: memberId}
            } else {
                let encryptingSenderKey = await this.StickProtocol.getEncryptingSenderKey(this.userId, stickId)
                encryptingSenderKey['preKeyId'] = preKeyId
                encryptingSenderKey['identityKeyId'] = identityKeyId
                encryptingSenderKey['stickId'] = stickId
                keys[memberId] = encryptingSenderKey
            }
        }

        // Upload the sender keys to the server
        await axios.post(`${this.URL}/api/upload-sks/`, {keys, users_id}, this.httpConfig)
    }


    /**
     * The following method is called before trying to decrypt a piece of data to check if there is an initialized sticky
     * session corresponding to that data's stickId. If there is no sticky session, it will try to fetch the sender key
     * from the server, and if it succeeds it will initialize the sticky session. This method returns a boolean indicating
     * whether the decryption process can proceed or not.
     */
    async canDecrypt(entityId, stickId, memberId, dispatch) {
        let canDecrypt = true
        const exists = await this.StickProtocol.sessionExists(memberId, stickId) // Check if the sticky session exists
        if (!exists) { // if the sticky session does not exists, then try to create it
            const body = {
                stickId, memberId, isDev: this.isDev,
                isInvitation: `${entityId}`.includes('invitation')
            }
            // try to fetch the sender key from the server
            if (!this.httpConfig.headers.Authorization) {
                await dispatch({type: 'PENDING_SESSION', payload: stickId})
                await dispatch({type: 'DOWNLOADED', payload: entityId});
                return canDecrypt
            }
            const {data} = await axios.post(`${this.URL}/api/fetch-sk/`, body, this.httpConfig)
            const senderKey = data.senderKey;
            if (!senderKey) { // If there is no sender key yet, mark the session as pending
                canDecrypt = false
                await dispatch({type: 'PENDING_SESSION', payload: stickId})
                await dispatch({type: 'DOWNLOADED', payload: entityId});
            } else { // otherwise initialize the session
                if (memberId !== this.userId)
                    await this.StickProtocol.initStickySession(memberId, stickId, senderKey.key, senderKey.identityKeyId)
                else {
                    senderKey.stickId = stickId
                    await this.StickProtocol.reinitMyStickySession(this.userId, senderKey)
                }
                await dispatch({type: 'PENDING_SESSION_DONE', payload: stickId})
            }
        } else { // If the sticky session exists, mark the session as not pending
            await dispatch({type: 'PENDING_SESSION_DONE', payload: stickId})
        }
        return canDecrypt; // return whether the sticky session has been initialized or not
    }


    // this function checks if a pairwise session exists, if not, it will fetch a PKB from the server and initialize
    // a new pairwise session. It checks for a pairwise session using a `oneTimeId`, which is an id assigned to a user
    // at registration time, and changes everytime the user relogs in.
    async checkPairwiseSession(userId, oneTimeId) {
        const exists = await this.StickProtocol.pairwiseSessionExists(oneTimeId)
        if (!exists) {
            const {data: pkb} = await axios.get(`${this.URL}/api/fetch-pkb/?id=${userId}&isSticky=false`, this.httpConfig)
            pkb.userId = oneTimeId
            await this.StickProtocol.initPairwiseSession(pkb)
        }
    }

    /**
     * This function is used to refill the prekeys of a user on the server
     * It takes two arguments:
     *  - nextPreKeyId: id of the next preKey for that user. The nextPreKeyId should be stored on the server.
     *  - count: how many preKeys to generate
     */
    async refillPreKeys(nextPreKeyId, count) {
        const preKeys = await this.StickProtocol.generatePreKeys(nextPreKeyId, count)
        await axios.post(`${this.URL}/api/upload-pre-keys/`, {
            preKeys,
            nextPreKeyId: nextPreKeyId + count
        }, this.httpConfig)
    }


    /**
     * A user can receive a pending key request, for a sender key that they have not uploaded yet for a user X.
     * When receiving a pending key request, the user needs to upload the corresponding sender key.
     * A pending key request has two parameters:
     *  - memberId: the userId from which the request comes from
     *  - stickId: the stickId of a sticky session
     *  It is preferable that this pending key requests go through a real time database.
     */
    async uploadPendingKey(memberId, stickId) {
        // Fetch preKeyBundle to create a new pairwise session to encrypt the sender key
        const {data: pkb} = await axios.get(`${this.URL}/api/fetch-pkb/?id=${memberId}`, this.httpConfig)
        // Init the session
        await this.StickProtocol.initPairwiseSession(pkb)
        const {preKeyId, identityKeyId} = pkb
        console.log('PPP', identityKeyId, preKeyId)
        if (memberId.length === 36 && stickId.length >= 36) {
            // Get the sender key and upload it
            const key = await this.StickProtocol.getSenderKey(this.userId, memberId, stickId, true);
            const body = {preKeyId, identityKeyId, key, stickId, forUser: memberId}
            await axios.post(`${this.URL}/api/upload-sk/`, body, this.httpConfig)
        }
    }

    /**
     * Before making an encryption in a sticky session, you need to make sure that this sticky session's chain is in
     * sync with the same sticky session chain on any other device for the currentUser.
     * This function takes two arguments:
     *  - step: the step number that the sticky session chain should be at. If there is no other devices to sync with,
     *  step value should be null.
     *  - stickId
     */
    async syncChain(step, stickId) {
        if (step) {
            const currentStep = await this.StickProtocol.getChainStep(this.userId, stickId)
            if (step > currentStep) {
                await this.StickProtocol.ratchetChain(this.userId, stickId, step - currentStep)
            }
        }
    }

    /**
     * The following function gets the active stickId associated with a partyId that already exists, and its current
     * chain step.
     */
    async getActiveStickId(partyId) {
        const res = await axios.post(`${this.URL}/api/get-active-stick-id/`, {partyId}, this.httpConfig)
        return {stickId: res.data.stickId, step: res.data.step};
    }

    /**
     * This function is used to fetch the sender key of a standard session from the server, and then init the session
     * if the server had the sender key.
     */
    async fetchStandardSenderKey(stickId, groupId, oneTimeId) {

        const keysToFetch = [oneTimeId]
        const response = await axios.post(`${this.URL}/api/fetch-standard-sks/`, {
            stickId,
            keysToFetch,
            groupId
        }, this.httpConfig)


        if (response.data.senderKeys[keysToFetch[0]])
            await this.StickProtocol.initStandardGroupSession(oneTimeId, stickId, response.data.senderKeys[keysToFetch[0]])
    }

    /**
     * This function check for the sender keys of a standard session that the current user has uploaded, and was
     * uploaded to them, and initializes the standard group sessions with other members if needed.
     * It takes 3 arguments:
     *  - groupId: UUID string identifying the group
     *  - stickId: UUID identifying the standard session ID for that group
     *  - members: an array of group members
     */
    async checkStandardSessionKeys(groupId, stickId, members) {
        let keysToFetch = [], keysToUpload = {};

        // loop over the group members to find which members the currentUser does not have a session with yet
        for (let i = 0; i < members.length; i++) {
            const member = members[i]
            if (member.id !== this.userId) {
                const oneTimeId = member.oneTimeId;
                await this.checkPairwiseSession(member.id, oneTimeId); // check pairwise session and create one if needed
                const exists = await this.StickProtocol.sessionExists(oneTimeId, stickId)

                // if there is no session, add the member's oneTimeId to the list of sessions that the user needs to init
                if (!exists)
                    keysToFetch.push(oneTimeId)
            }
        }

        // Try to fetch the standard session sender keys from the server, and create group sessions
        if (keysToFetch.length > 0) {
            const response = await axios.post(`${this.URL}/api/fetch-standard-sks/`, {
                stickId,
                keysToFetch,
                groupId
            }, this.httpConfig)
            for (let i = 0; i < keysToFetch.length; i++) {
                if (response.data.senderKeys[keysToFetch[i]]) {
                    await this.StickProtocol.initStandardGroupSession(keysToFetch[i], stickId, response.data.senderKeys[keysToFetch[i]])
                }
            }
        }

        // Get from the server which members the currentUser have not yet uploaded their sender key to
        const res = await axios.post(`${this.URL}/api/fetch-uploaded-sks/`, {
            groups_ids: [groupId],
            connections_ids: [],
            isSticky: false,
            stickId
        }, this.httpConfig)

        // Upload sender keys to those members that do not have the sender key yet
        for (let i = 0; i < members.length; i++) {
            const member = members[i]
            if (member.id !== this.userId) {
                if (!res.data.members[member.oneTimeId].exists) {
                    keysToUpload[member.oneTimeId] = await this.StickProtocol.getSenderKey(this.userOneTimeId, member.oneTimeId, stickId, false);
                }
            }
        }
        if (Object.values(keysToUpload).length > 0)
            await axios.post(`${this.URL}/api/upload-standard-sks/`, {stickId, keysToUpload}, this.httpConfig)
    }

    /**
     * This function check if the current active signed prekey needs to be updated. If needed, it will generate a new
     * SPK and send to the server.
     */
    async refreshSignedPreKey() {
        const result = await this.StickProtocol.refreshSignedPreKey()
        if (result) {
            await axios.post(`${this.URL}/api/update-active-spk/`, result, this.httpConfig)
        }
    }

    /**
     * This function check if the current active identity key needs to be updated. If needed, it will generate a new
     * identity key and send it to the server.
     */
    async refreshIdentityKey() {
        const result = await this.StickProtocol.refreshIdentityKey()
        if (result) {
            await axios.post(`${this.URL}/api/update-active-ik/`, result, this.httpConfig)
        }
    }


    /**
     * A helper function to reset the auth token, userId or oneTimeId
     */
    setToken(token, userId, userOneTimeId) {
        this.token = token
        this.httpConfig = {headers: {"Authorization": token}}
        console.log('SETTING TOKEN DONE', this.httpConfig)
        this.userId = userId
        this.userOneTimeId = userOneTimeId
    }
}