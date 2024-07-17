/*
 *  Copyright © 2018-2022 Sticknet.
 *
 *  This source code is licensed under the GPLv3 license found in the
 *  LICENSE file in the root directory of this source tree.
 */

import type { TDecryptionSenderKey } from './Keys';

/**
 *  This class contains common handler methods needed for the StickProtocol client-side. These handlers may differ
 *  from one application to another. So, you are free to write your own handlers. These handlers can be implemented
 *  using Java/Kotlin/Swift/Objective-C or any other programming language. This file is an example implementation of
 *  the StickProtocolHandlers in TypeScript.
 *
 *  @author Omar Basem
 */

export type StickProtocol = {
    initPairwiseSession: (bundle: any) => Promise<void>;
    getSenderKey: (userId: string, memberId: string, stickId: string, encrypt: boolean) => Promise<any>;
    createStickySession: (userId: string, stickId: string) => Promise<any>;
    sessionExists: (memberId: string, stickId: string) => Promise<boolean>;
    reinitMyStickySession: (userId: string, senderKey: any) => Promise<void>;
    initStickySession: (memberId: string, stickId: string, key: string, identityKeyId: number) => Promise<void>;
    pairwiseSessionExists: (oneTimeId: string) => Promise<boolean>;
    generatePreKeys: (nextPreKeyId: number, count: number) => Promise<any>;
    getChainStep: (userId: string, stickId: string) => Promise<number>;
    ratchetChain: (userId: string, stickId: string, steps: number) => Promise<void>;
    refreshSignedPreKey: () => Promise<any>;
    refreshIdentityKey: () => Promise<any>;
    initStandardGroupSession: (oneTimeId: string, stickId: string, senderKey: any) => Promise<void>;
};

export type StickProtocolHandlersData = {
    axios: any;
    userId: string;
    userOneTimeId: string;
    URL: string;
    token: string;
};

interface FetchSKResponse {
    partyExists: boolean;
    senderKey?: TDecryptionSenderKey;
}

export default class StickProtocolHandlers {
    StickProtocol: StickProtocol;
    axios: any;
    userId: string;
    userOneTimeId: string;
    URL: string;
    token: string;
    httpConfig: { headers: { Authorization: string } };

    constructor(StickProtocol: StickProtocol, data: StickProtocolHandlersData) {
        this.StickProtocol = StickProtocol;
        this.axios = data.axios;
        this.userId = data.userId;
        this.userOneTimeId = data.userOneTimeId;
        this.URL = data.URL;
        this.token = data.token;
        this.httpConfig = { headers: { Authorization: data.token } };
    }

    async getStickId(
        groups: Array<{ id: string } | string>,
        connections: Array<{ id: string } | string>,
        isProfile: boolean,
        type: 'group' | 'multi' | 'self',
        providedPartyId: string | null = null
    ) {
        const userId = this.userId;
        let groupsIds: string[] = [],
            connectionsIds: string[] = [];

        if (type === 'multi') {
            if (!isProfile) {
                groupsIds = groups.map((group) => (typeof group === 'string' ? group : group.id));
                connectionsIds = connections.map((connection) => (typeof connection === 'string' ? connection : connection.id));
            } else {
                connectionsIds = connections.map((connection) => (typeof connection === 'string' ? connection : connection.id));
                connectionsIds.push(userId);
            }
        } else if (type === 'group') {
            groupsIds = [typeof groups[0] === 'string' ? groups[0] : groups[0].id];
        } else if (type === 'self') {
            connectionsIds = [userId];
        }

        connectionsIds = connectionsIds.filter((id) => id !== null);

        let body: any = {
            groupsIds,
            connectionsIds,
            isSticky: true,
            isProfile,
            type,
        };
        if (providedPartyId) body.partyId = providedPartyId;

        const res = await this.axios.post(`${this.URL}/api/fetch-uploaded-sks/`, body, this.httpConfig);
        const stickId = res.data.stickId;
        const partyId = res.data.partyId;
        const usersId = res.data.bundlesToFetch;

        if (usersId.length > 0) {
            await this.uploadSenderKeys(stickId, usersId);
        }

        await this.syncChain(res.data.step, stickId);

        return { partyId, stickId, groupsIds, connectionsIds };
    }

    async uploadSenderKeys(stickId: string, usersId: string[] | null = null, groupId: string | null = null) {
        const data = usersId ? { usersId } : { groupId };
        const bundlesRes = await this.axios.post(`${this.URL}/api/fetch-pkbs/`, data, this.httpConfig);
        const { bundles } = bundlesRes.data;
        usersId = bundlesRes.data.usersId;
        const keys: any = {};

        for (let i = 0; i < usersId!.length; i++) {
            const memberId = usersId![i];
            await this.StickProtocol.initPairwiseSession(bundles[memberId]);
            const preKeyId = bundles[memberId].preKeyId;
            const identityKeyId = bundles[memberId].identityKeyId;

            if (memberId === this.userId) {
                const encryptionSenderKey = await this.StickProtocol.createStickySession(this.userId, stickId);
                encryptionSenderKey['preKeyId'] = preKeyId;
                encryptionSenderKey['identityKeyId'] = identityKeyId;
                encryptionSenderKey['stickId'] = stickId;
                keys[memberId] = encryptionSenderKey;
            } else {
                const key = await this.StickProtocol.getSenderKey(this.userId, memberId, stickId, true);
                keys[memberId] = { identityKeyId, preKeyId, key, stickId, forUser: memberId };
            }
        }

        await this.axios.post(`${this.URL}/api/upload-sks/`, { keys, usersId }, this.httpConfig);
    }

    async canDecrypt(
        entityId: string,
        stickId: string,
        memberId: string,
        fetchingSenderKeys: { [key: string]: boolean },
        successCallback: () => void,
        pendingCallback: () => void
    ): Promise<{ canDecrypt: boolean; partyExists: boolean }> {
        let canDecrypt = true;
        let data: FetchSKResponse = { partyExists: true };
        const sessionExists = await this.StickProtocol.sessionExists(memberId, stickId);

        if (!sessionExists) {
            const body = { stickId, memberId, isInvitation: `${entityId}`.includes('invitation') };

            if (!this.httpConfig.headers.Authorization) {
                pendingCallback();
                return { canDecrypt: false, partyExists: true };
            }

            if (!fetchingSenderKeys[stickId + memberId]) {
                fetchingSenderKeys[stickId + memberId] = true;
                const response = await this.axios.post(`${this.URL}/api/fetch-sk/`, body, this.httpConfig);
                data = { ...data, ...response.data };

                if (!data.partyExists) {
                    return { canDecrypt: false, partyExists: false };
                }

                const senderKey = data.senderKey;

                if (!senderKey) {
                    pendingCallback();
                    canDecrypt = false;
                } else {
                    fetchingSenderKeys[stickId + memberId] = false;
                    if (memberId !== this.userId) {
                        await this.StickProtocol.initStickySession(memberId, stickId, senderKey.key, senderKey.identityKeyId);
                    } else {
                        senderKey.stickId = stickId;
                        await this.StickProtocol.reinitMyStickySession(this.userId, senderKey);
                    }
                    successCallback();
                }
            } else {
                pendingCallback();
                return { canDecrypt: false, partyExists: true };
            }
        } else {
            successCallback();
        }

        return { canDecrypt, partyExists: true };
    }

    async checkPairwiseSession(userId: string, oneTimeId: string) {
        const exists = await this.StickProtocol.pairwiseSessionExists(oneTimeId);

        if (!exists) {
            const { data: pkb } = await this.axios.get(`${this.URL}/api/fetch-pkb/?id=${userId}&isSticky=false`, this.httpConfig);
            pkb.userId = oneTimeId;
            await this.StickProtocol.initPairwiseSession(pkb);
        }
    }

    async refillPreKeys(nextPreKeyId: number, count: number) {
        const preKeys = await this.StickProtocol.generatePreKeys(nextPreKeyId, count);
        await this.axios.post(
            `${this.URL}/api/upload-pre-keys/`,
            { preKeys, nextPreKeyId: nextPreKeyId + count },
            this.httpConfig
        );
    }

    async uploadPendingKey(memberId: string, stickId: string) {
        const { data: pkb } = await this.axios.get(`${this.URL}/api/fetch-pkb/?id=${memberId}`, this.httpConfig);
        await this.StickProtocol.initPairwiseSession(pkb);
        const { preKeyId, identityKeyId } = pkb;

        if (memberId.length === 36 && stickId.length >= 36) {
            const key = await this.StickProtocol.getSenderKey(this.userId, memberId, stickId, true);
            const body = { preKeyId, identityKeyId, key, stickId, forUser: memberId };
            await this.axios.post(`${this.URL}/api/upload-sk/`, body, this.httpConfig);
        }
    }

    async syncChain(step: number, stickId: string) {
        if (step) {
            const currentStep = await this.StickProtocol.getChainStep(this.userId, stickId);
            if (step > currentStep) {
                await this.StickProtocol.ratchetChain(this.userId, stickId, step - currentStep);
            }
        }
    }

    async getActiveStickId(partyId: string) {
        const res = await this.axios.post(`${this.URL}/api/get-active-stick-id/`, { partyId }, this.httpConfig);
        return { stickId: res.data.stickId, step: res.data.step };
    }

    async fetchStandardSenderKey(stickId: string, groupId: string, oneTimeId: string) {
        const keysToFetch = [oneTimeId];
        const response = await this.axios.post(
            `${this.URL}/api/fetch-standard-sks/`,
            { stickId, keysToFetch, groupId },
            this.httpConfig
        );

        if (response.data.senderKeys[keysToFetch[0]]) {
            await this.StickProtocol.initStandardGroupSession(oneTimeId, stickId, response.data.senderKeys[keysToFetch[0]]);
        }
    }

    async checkStandardSessionKeys(groupId: string, stickId: string, members: Array<{ id: string; oneTimeId: string }>) {
        const keysToFetch: string[] = [];
        const keysToUpload: { [key: string]: any } = {};

        for (const member of members) {
            if (member.id !== this.userId) {
                await this.checkPairwiseSession(member.id, member.oneTimeId);
                const exists = await this.StickProtocol.sessionExists(member.oneTimeId, stickId);

                if (!exists) {
                    keysToFetch.push(member.oneTimeId);
                }
            }
        }

        if (keysToFetch.length > 0) {
            const response = await this.axios.post(
                `${this.URL}/api/fetch-standard-sks/`,
                { stickId, keysToFetch, groupId },
                this.httpConfig
            );

            for (const keyToFetch of keysToFetch) {
                if (response.data.senderKeys[keyToFetch]) {
                    await this.StickProtocol.initStandardGroupSession(keyToFetch, stickId, response.data.senderKeys[keyToFetch]);
                }
            }
        }

        const res = await this.axios.post(
            `${this.URL}/api/fetch-uploaded-sks/`,
            { groupsIds: [groupId], connectionsIds: [], isSticky: false, stickId },
            this.httpConfig
        );

        for (const member of members) {
            if (member.id !== this.userId) {
                if (!res.data.members[member.oneTimeId].exists) {
                    keysToUpload[member.oneTimeId] = await this.StickProtocol.getSenderKey(
                        this.userOneTimeId,
                        member.oneTimeId,
                        stickId,
                        false
                    );
                }
            }
        }

        if (Object.values(keysToUpload).length > 0) {
            await this.axios.post(`${this.URL}/api/upload-standard-sks/`, { stickId, keysToUpload }, this.httpConfig);
        }
    }

    async refreshSignedPreKey() {
        const result = await this.StickProtocol.refreshSignedPreKey();
        if (result) {
            await this.axios.post(`${this.URL}/api/update-active-spk/`, result, this.httpConfig);
        }
    }

    async refreshIdentityKey() {
        const result = await this.StickProtocol.refreshIdentityKey();
        if (result) {
            await this.axios.post(`${this.URL}/api/update-active-ik/`, result, this.httpConfig);
        }
    }

    async setUp(token: string, userId: string, userOneTimeId: string) {
        this.token = token;
        this.httpConfig = { headers: { Authorization: token } };
        this.userId = userId;
        this.userOneTimeId = userOneTimeId;
    }
}
