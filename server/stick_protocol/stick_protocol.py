#   Copyright © 2018-2021 STiiiCK.
#
#   This source code is licensed under the GPLv3 license found in the
#   LICENSE file in the root directory of this source tree.

import uuid, hashlib

from .models import IdentityKey, SignedPreKey, PreKey, EncryptionSenderKey, DecryptionSenderKey, PendingKey, Party
from django.db.models import Q, Count
from firebase_admin import db
from django.conf import settings
from django.utils.dateformat import format


#
# @author Omar Basem
#

class StickProtocol():

    def __init__(self, UserModel, DeviceModel, GroupModel, sessionAge):
        self.User = UserModel
        self.Device = DeviceModel
        self.Group = GroupModel
        self.sessionAge = sessionAge

    def process_pre_key_bundle(self, data, user):
        """
        A user must upload their PreKeyBundles at registration time. Before uploading their PreKeyBundles, they need to verify
        their phone number, and get their LimitedAccessToken.
        """
        identityKey = data["identityKey"]
        signedPreKey = data["signedPreKey"]
        preKeys = data["preKeys"]
        IdentityKey.objects.create(keyId=identityKey['id'], public=identityKey['public'],
                                   user=user, cipher=identityKey['cipher'], salt=identityKey['salt'],
                                   timestamp=identityKey['timestamp'], active=True)
        SignedPreKey.objects.create(public=signedPreKey['public'], signature=signedPreKey["signature"],
                                    keyId=signedPreKey['id'], user=user, cipher=signedPreKey['cipher'],
                                    salt=signedPreKey['salt'], timestamp=signedPreKey['timestamp'], active=True)
        for preKey in preKeys:
            PreKey.objects.create(public=preKey['public'], keyId=preKey["id"], user=user, cipher=preKey['cipher'],
                                  salt=preKey['salt'])
        user.passwordSalt = data["passwordSalt"]
        user.set_password(data["passwordHash"])  # This will create a "Double-Hashed" password
        user.oneTimeId = data["oneTimeId"]
        user.localId = data['localId']
        user.nextPreKeyId = data['nextPreKeyId']
        user.finishedRegistration = True
        user.save()
        self.Device.objects.create(user=user, deviceId=data['deviceId'], name=data['deviceName'], chatId=data['oneTimeId'])
        Party.objects.create(user=user)
        Party.objects.create(user=user, individual=True)

    def process_pre_keys(self, data, user):
        """
        A user would need to refill their PreKeys on the server every while whenever it goes below a certain N value.
        This method save preKeys and updates the nextPreKeyId value
        """
        preKeys = data['preKeys']
        for preKey in preKeys:
            PreKey.objects.create(public=preKey['public'], keyId=preKey["id"], user=user, cipher=preKey['cipher'],
                                  salt=preKey['salt'])
        user.nextPreKeyId = data['nextPreKeyId']
        user.save()

    def get_pre_key_bundle(self, data):
        """
        The following get method is used to fetch the PreKeyBundle of user to create a pairwise signal session. The request must contain
        a boolean `isSticky` to know whether this bundle would be used to communicate a SenderKey or not. If it will be used to
        communicate a SenderKey, then the PreKey must be marked as used, otherwise the PreKey is deleted from the server.
        """
        userId = data['userId']
        isSticky = data['isSticky']
        user = self.User.objects.get(id=userId)
        identityKey = IdentityKey.objects.get(user=user, active=True)
        signedPreKey = SignedPreKey.objects.get(user=user, active=True)
        preKey = PreKey.objects.filter(user=user, used=False).first()
        PKB = {
            "identityKey": identityKey.public,
            "identityKeyId": identityKey.keyId,
            "userId": userId,
            "localId": user.localId,
            "signedPreKey": signedPreKey.public,
            "signedPreKeyId": signedPreKey.keyId,
            "signature": signedPreKey.signature,
            "oneTimeId": user.oneTimeId,
        }
        if preKey:
            PKB["preKey"] = preKey.public
            PKB["preKeyId"] = preKey.keyId
            if not isSticky:
                preKey.delete()
            elif preKey:
                preKey.used = True
                preKey.save()
        return PKB

    def get_pre_key_bundles(self, currentUser, users_id):
        """
        Similar to the above method, but fetches PreKeyBundles of several users at once. This method allows a user to
        communicate their SenderKey to multiple members of a party at once.
        """
        bundles = {}
        # Make sure the current user is the first in the list. When creating DecryptionSenderKeys client-side to share
        # with other members, their must already be a corresponding EncryptionSenderKey.
        if currentUser.id in users_id:
            users_id.remove(currentUser.id)
            users_id.insert(0, currentUser.id)

        toBeRemoved = []
        for id in users_id:
            # If a non-existent user_id was provided, then their id must be removed from the list
            try:
                identityKey = IdentityKey.objects.get(user__id=id, active=True)
            except:
                toBeRemoved.append(id)
                continue
            signedPreKey = SignedPreKey.objects.get(user__id=id, active=True)
            preKey = PreKey.objects.filter(user__id=id, used=False).first()
            user = self.User.objects.get(id=id)
            PKB = {
                "identityKey": identityKey.public,
                "identityKeyId": identityKey.keyId,
                "localId": user.localId,
                "userId": id,
                "oneTimeId": user.oneTimeId,
                "signedPreKey": signedPreKey.public,
                "signedPreKeyId": signedPreKey.keyId,
                "signature": signedPreKey.signature,
            }
            if preKey:
                PKB["preKey"] = preKey.public
                PKB["preKeyId"] = preKey.keyId
                preKey.used = True
                preKey.save()
            bundles[id] = PKB
        for id in toBeRemoved:
            users_id.remove(id)
        dict = {"bundles": bundles, "users_id": users_id}
        return dict

    def get_sender_key(self, data, user):
        """
        This method is used to fetch the SenderKey of a stickySession.
        The body should contain the following fields:
            * stickId - String
            * memberId - String
            * isSticky - Boolean (are you fetching the SenderKey of a Sticky session or a standard session)
            * isInvitation - Boolean
        """
        memberId = data['memberId']
        stickId = data['stickId']
        isInvitation = False
        if 'isInvitation' in data:
            isInvitation = data['isInvitation']
        try:
            member = self.User.objects.get(id=memberId)
        except:
            member = self.User.objects.filter(oneTimeId=memberId).first()
            if not member:
                return {'partyExists': False}

        # You need to check whether the user is authorized to fetch that SenderKey
        authorized = False
        partyExists = True
        if user in member.blocked.all():  # A blocked user is not authorized
            return {'authorized': authorized}
        if isInvitation:  # An invited user is authorized
            group = self.Group.objects.get(id=stickId[:36])
            if group in user.invited_groups.all():
                authorized = True
        elif stickId.startswith(user.parties.get(individual=False).id) or stickId.startswith(user.parties.get(
                individual=True).id):  # A user is authorized to fetch SenderKeys of their own profile (user.party.id)
            authorized = True
        else:
            groupId = stickId[:36]
            group = self.Group.objects.filter(id=groupId).first()
            if group:
                if group in user.groups.all():  # A group member is authorized
                    authorized = True
            else:
                party = Party.objects.filter(id=stickId[:36]).first()
                if not party:
                    return {'partyExists': False}
                # A user connected with another user should be authorized
                if party.user and (user in party.user.connections.all() or user.phone in party.user.contacts):
                    authorized = True
                else:
                    if user in party.connections.all():  # A user in the connections list of a party should be authorized
                        authorized = True
                    else:
                        userGroups = user.groups.all()
                        for group in party.groups.all():
                            if group in userGroups:  # If a Party and a User have a mutual Group, then that user is authorized
                                authorized = True
                                break
        if not authorized:  # if NOT authorized, return 401
            return {'authorized': authorized}

        if memberId != user.id:  # Trying to fetch DSK
            senderKey = DecryptionSenderKey.objects.filter(stickId=stickId, ofUser=memberId,
                                                           forUser=user).first()
        else:  # Trying to fetch ESK
            partyId = stickId[:36]
            chainId = stickId[36:]
            senderKey = EncryptionSenderKey.objects.filter(partyId=partyId, chainId=chainId, user=user).first()
        key = None
        phone = None
        if senderKey:  # If the SenderKey exists, we will return it
            if memberId != user.id:
                key = {'key': senderKey.key, 'identityKeyId': senderKey.identityKey.keyId}
            else:
                key = {'id': senderKey.keyId, 'key': senderKey.key, 'step': senderKey.step,
                       'identityKeyId': senderKey.identityKey.keyId}
        # SenderKey does not exist, send a `PendingKey` request to the target user to upload their key,
        # through a realtime database.
        else:
            if not PendingKey.objects.filter(user=user, stickId=stickId).exists():
                PendingKey.objects.create(user=user, owner=member, stickId=stickId)
                phone = member.phone
        return {'authorized': authorized, 'senderKey': key, 'phone': phone, 'partyExists': partyExists}

    def get_standard_sender_keys(self, data, user, group):
        """
        This method is used to fetch the standard session sender keys of a group.
        """
        stickId = data['stickId']
        keysToFetch = data['keysToFetch']
        if group not in user.groups.all():
            return {'authorized': False}
        senderKeys = {}
        for id in keysToFetch:
            senderKey = DecryptionSenderKey.objects.filter(stickId=stickId, ofOneTimeId=id,
                                                           forOneTimeId=user.oneTimeId).first()
            key = None
            if senderKey:
                key = senderKey.key
                # senderKey.delete()
            senderKeys[id] = key
        return {'authorized': True, 'senderKeys': senderKeys}

    def get_stick_id(self, data, user):
        groups_ids = data['groups_ids']
        connections_ids = data['connections_ids']
        isSticky = data['isSticky']
        isProfile = False
        if 'isProfile' in data:
            isProfile = data['isProfile']
        membersIds = []
        if not isProfile and 'partyId' not in data:
            if len(groups_ids) == 1 and len(connections_ids) == 0:  # Sharing with a single group
                if isSticky:  # Using sticky session
                    membersIds = self.Group.objects.get(id=groups_ids[0]).get_members_ids()
                    partyId = groups_ids[0]
                else:  # Using standard session
                    membersIds = self.Group.objects.get(id=groups_ids[0]).get_members_otids()
                    partyId = data["stickId"]
            else:  # Sharing with a collection of groups and/or users
                if len(connections_ids) > 0 and user.id not in connections_ids:
                    connections_ids.append(user.id)
                groups_ids.sort()
                connections_ids.sort()
                ids = ''.join(groups_ids + connections_ids)
                h = hashlib.sha256()
                h.update(ids.encode())
                partyHash = h.hexdigest()
                party = Party.objects.filter(partyHash=partyHash).first()
                if party == None:  # Create a new Party object if does not exist
                    party = Party.objects.create(partyHash=partyHash)
                    party.groups.set(groups_ids)
                    party.connections.set(connections_ids)
                for group_id in groups_ids:
                    group = self.Group.objects.get(id=group_id)
                    for memberId in group.get_members_ids():
                        if not memberId in membersIds:
                            membersIds.append(memberId)
                for connection_id in connections_ids:
                    if not connection_id in membersIds:
                        membersIds.append(connection_id)
                if user.id not in membersIds:
                    membersIds.append(user.id)
                partyId = party.id
        elif 'partyId' in data:
            membersIds = [user.id]
            if not (len(groups_ids) == 1 and len(connections_ids) == 0):
                party = Party.objects.get(id=data['partyId'])
                if party.user and party.user.id != user.id:
                    membersIds.append(party.user.id)
            partyId = data['partyId']
        else:  # Sharing to the currentUser's party (currentUsers' profile)
            membersIds = connections_ids
            isIndividual = data['type'] == 'individual'
            partyId = Party.objects.get(user=user, individual=isIndividual).id
        dict = {}
        bundlesToFetch = []
        responseDict = {}

        # Find the right stickId
        chainId = 0
        senderKeys = EncryptionSenderKey.objects.filter(partyId=partyId, user=user).order_by('-chainId')
        if len(senderKeys) > 0:
            activeSenderKey = senderKeys[0]
            if not isSticky:  # A standard session is valid
                dict[user.id] = {'exists': True}
            elif activeSenderKey.step < self.sessionAge:  # Check whether is sticky session has not expired
                chainId = activeSenderKey.chainId
                dict[user.id] = {'exists': True}
                responseDict["step"] = activeSenderKey.step
            else:  # Sticky session has expired, increment chainId by 1
                chainId = activeSenderKey.chainId + 1
                dict[user.id] = {'exists': False}
                if user.id not in membersIds:
                    bundlesToFetch.append(user.id)
        else:
            dict[user.id] = {'exists': False}
        stickId = str(partyId) + str(chainId)

        if not isSticky:
            stickId = partyId

        for memberId in membersIds:  # loop of the target users and check if they have their SenderKey
            if isSticky:
                if user.id != memberId:
                    senderKey = DecryptionSenderKey.objects.filter(stickId=stickId, ofUser=user,
                                                                   forUser=memberId).first()
                else:
                    senderKey = EncryptionSenderKey.objects.filter(partyId=partyId, chainId=chainId,
                                                                   user=user).first()
            else:
                senderKey = DecryptionSenderKey.objects.filter(stickId=stickId, ofOneTimeId=user.oneTimeId,
                                                               forOneTimeId=memberId).first()
            if senderKey:
                response = {'exists': True}
            else:
                response = {'exists': False}
                bundlesToFetch.append(memberId)
            dict[memberId] = response
        responseDict["stickId"] = stickId
        responseDict["partyId"] = partyId
        responseDict["members"] = dict
        if user.id in bundlesToFetch:
            bundlesToFetch.remove(user.id)
            bundlesToFetch.insert(0, user.id)
        responseDict["bundlesToFetch"] = bundlesToFetch
        return responseDict

    def get_active_stick_id(self, data, currentUser):
        """
        This method gets the active sticky session stickId associated with a particular partyId that already exists, and
        its current step.
        """
        partyId = data['partyId']
        senderKeys = EncryptionSenderKey.objects.filter(partyId=partyId, user=currentUser).order_by('-chainId')
        activeSenderKey = senderKeys[0]
        responseDict = {}
        if activeSenderKey.step < self.sessionAge:
            chainId = activeSenderKey.chainId
            responseDict['step'] = activeSenderKey.step
        else:
            chainId = activeSenderKey.chainId + 1
        responseDict['stickId'] = str(partyId) + str(chainId)
        return responseDict

    def process_sender_key(self, data, user):
        """
        This method is used to save a SenderKey of a sticky session for a user. Typically used when a user
        receives a `PendingKey` request.
        """
        preKey = PreKey.objects.get(keyId=data['preKeyId'], user__id=data['forUser'])
        forUser = self.User.objects.get(id=data['forUser'])
        identityKey = IdentityKey.objects.get(keyId=data['identityKeyId'], user__id=data['forUser'])
        decryptingSenderKey = DecryptionSenderKey.objects.create(key=data['key'],
                                                                 stickId=data['stickId'], ofUser=user, forUser=forUser,
                                                                 preKey=preKey, identityKey=identityKey)
        decryptingSenderKey.save()

    def process_sender_keys(self, data, user):
        """
        This method is used to save SenderKeys of multiple users at once. Before making an upload, and after
        the user has made a request to get the UploadedSenderKeys, and now knows which users does not have SenderKeys for
        a particular sticky session, the user can upload those SenderKeys through this method.
        """
        users_id = data['users_id']
        keys = data['keys']
        for id in users_id:
            senderKey = keys[id]
            preKey = PreKey.objects.get(keyId=senderKey['preKeyId'], user__id=id)
            identityKey = IdentityKey.objects.get(keyId=senderKey['identityKeyId'], user__id=id)
            if id != user.id:  # Other user? Create a DSK
                forUser = self.User.objects.get(id=senderKey['forUser'])
                DecryptionSenderKey.objects.create(key=senderKey['key'],
                                                   stickId=senderKey['stickId'], ofUser=user,
                                                   preKey=preKey, identityKey=identityKey, forUser=forUser)
            else:  # Current user? Create an ESK
                partyId = senderKey['stickId'][:36]
                chainId = senderKey['stickId'][36:]
                EncryptionSenderKey.objects.create(keyId=senderKey['id'], preKey=preKey, identityKey=identityKey,
                                                   partyId=partyId, chainId=chainId,
                                                   user=user, key=senderKey['key'])

    def process_standard_sender_keys(self, data, user):
        """
        This method is used to upload the SenderKeys of a standard session.
        """
        stickId = data['stickId']
        keysToUpload = data['keysToUpload']
        for oneTimeId, senderKey in keysToUpload.items():
            DecryptionSenderKey.objects.create(key=senderKey, stickId=stickId, ofUser=user,
                                               forOneTimeId=oneTimeId, ofOneTimeId=user.oneTimeId)

    def update_active_spk(self, data, user):
        """
        This method is used to update the active signed prekey for a user
        """
        old_spk = SignedPreKey.objects.get(user=user, active=True)
        old_spk.active = False
        old_spk.save()
        SignedPreKey.objects.create(user=user, public=data['public'], signature=data["signature"],
                                    keyId=data['id'], cipher=data['cipher'], salt=data['salt'],
                                    timestamp=data['timestamp'], active=True)

    def update_active_ik(self, data, user):
        """
        This method is used to update the active identity key for a user
        """
        old_ik = IdentityKey.objects.get(user=user, active=True)
        old_ik.active = False
        old_ik.save()
        IdentityKey.objects.create(user=user, public=data['public'],
                                   keyId=data['id'], cipher=data['cipher'], salt=data['salt'],
                                   timestamp=data['timestamp'], active=True)

    def verify_password_and_get_keys(self, data, user):
        """
        This Login method should be called after the user have verified their phone number and got their LimitedAccessToken.
        As a 2FA mechanism, the user need to provide their password (initial password hash). If the password is correct,
        return to the user their keys:
            * Identity Keys
            * Signed Pre Keys
            * Pre Keys
            * Encrypting Sender Keys
        On the client-side, the password will be used to decrypt the private keys of the IdentityKey, SignedPreKey
        and PreKeys (using a secret key derived from the password through Argon2).
        The user will be able to re-establish their pairwise signal sessions. After that, the user can decrypt their ESKs
        as well as any of the DSKs the was sent to them, which they can fetch again from the server as needed.
        """
        if user.check_password(data['passwordHash']):  # This will create a "double-hash" and verify it
            signedPreKeysList = SignedPreKey.objects.filter(user=user)
            identityKeysList = IdentityKey.objects.filter(user=user)
            preKeysList = PreKey.objects.filter(user=user).order_by('-dt_timestamp')
            senderKeysList = EncryptionSenderKey.objects.filter(user=user)
            bundle = {'localId': user.localId}
            identityKeys = []
            for ik in identityKeysList:
                key = {'id': ik.keyId, 'public': ik.public, 'cipher': ik.cipher, 'salt': ik.salt, 'active': ik.active,
                       'timestamp': ik.timestamp}
                identityKeys.append(key)
            bundle['identityKeys'] = identityKeys
            signedPreKeys = []
            for spk in signedPreKeysList:
                key = {'id': spk.keyId, 'public': spk.public, 'cipher': spk.cipher, 'salt': spk.salt,
                       'signature': spk.signature, 'active': spk.active, 'timestamp': spk.timestamp}
                signedPreKeys.append(key)
            bundle['signedPreKeys'] = signedPreKeys
            preKeys = []
            for preKey in preKeysList:
                key = {'id': preKey.keyId, 'public': preKey.public, 'cipher': preKey.cipher, 'salt': preKey.salt,
                       'used': preKey.used}
                preKeys.append(key)
            bundle['preKeys'] = preKeys
            senderKeys = []
            for senderKey in senderKeysList:
                stickId = senderKey.partyId + str(senderKey.chainId)
                key = {'id': senderKey.keyId, 'key': senderKey.key, 'stickId': stickId, 'step': senderKey.step,
                       'identityKeyId': senderKey.identityKey.keyId, 'preKeyId': senderKey.preKey.keyId}
                senderKeys.append(key)
            bundle['senderKeys'] = senderKeys
            user.save()
            device = self.Device.objects.filter(user=user, deviceId=data['deviceId']).first()
            if not device:
                device = self.Device.objects.create(user=user, deviceId=data['deviceId'], name=data['deviceName'], chatId=uuid.uuid4())
            else:
                device.chatId = uuid.uuid4()
            bundle['oneTimeId'] = device.chatId
            return {"bundle": bundle, "verify": True}
        else:
            return {"verify": False}

    def process_reencrypted_keys(self, data, user):
        success = False
        if user.check_password(data['currentPass']):
            for key in data['preKeys']:
                preKey = PreKey.objects.filter(keyId=key['id'], user=user).first()
                if preKey:
                    preKey.cipher = key['cipher']
                    preKey.salt = key['salt']
                    preKey.save()
            for key in data['signedPreKeys']:
                spk = SignedPreKey.objects.get(keyId=key['id'], user=user)
                spk.cipher = key['cipher']
                spk.salt = key['salt']
                spk.save()
            for key in data['identityKeys']:
                ik = IdentityKey.objects.get(keyId=key['id'], user=user)
                ik.cipher = key['cipher']
                ik.salt = key['salt']
                ik.save()
            user.passwordSalt = data["newSalt"]
            user.set_password(data["newPass"])
            user.save()
            success = True
        return {"success": success}
