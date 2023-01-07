#   Copyright © 2018-2022 StickNet.
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

    def __init__(self, UserModel, DeviceModel, GroupModel, session_life_cycle):
        self.User = UserModel
        self.Device = DeviceModel
        self.Group = GroupModel
        self.session_life_cycle = session_life_cycle

    def process_pre_key_bundle(self, data, user):
        """
        A user must upload their PreKeyBundles at registration time. Before uploading their PreKeyBundles, they need to verify
        their phone number, and get their LimitedAccessToken.
        """
        identity_key = data['identity_key']
        signed_pre_key = data['signed_pre_key']
        pre_keys = data['pre_keys']
        IdentityKey.objects.create(key_id=identity_key['id'], public=identity_key['public'],
                                   user=user, cipher=identity_key['cipher'], salt=identity_key['salt'],
                                   timestamp=identity_key['timestamp'], active=True)
        SignedPreKey.objects.create(public=signed_pre_key['public'], signature=signed_pre_key['signature'],
                                    key_id=signed_pre_key['id'], user=user, cipher=signed_pre_key['cipher'],
                                    salt=signed_pre_key['salt'], timestamp=signed_pre_key['timestamp'], active=True)
        for pre_key in pre_keys:
            PreKey.objects.create(public=pre_key['public'], key_id=pre_key['id'], user=user, cipher=pre_key['cipher'],
                                  salt=pre_key['salt'])
        user.password_salt = data['password_salt']
        user.set_password(data['password_hash'])  # This will create a "Double-Hashed" password
        user.one_time_id = data['one_time_id']
        user.local_id = data['local_id']
        user.next_pre_key_id = data['next_pre_key_id']
        user.finished_registration = True
        user.save()
        self.Device.objects.create(user=user, device_id=data['device_id'], name=data['device_name'], chat_id=data['one_time_id'])
        Party.objects.create(user=user)
        Party.objects.create(user=user, individual=True)

    def process_pre_keys(self, data, user):
        """
        A user would need to refill their PreKeys on the server every while whenever it goes below a certain N value.
        This method save pre_keys and updates the next_pre_key_id value
        """
        pre_keys = data['pre_keys']
        for pre_key in pre_keys:
            PreKey.objects.create(public=pre_key['public'], key_id=pre_key['id'], user=user, cipher=pre_key['cipher'],
                                  salt=pre_key['salt'])
        user.next_pre_key_id = data['next_pre_key_id']
        user.save()

    def get_pre_key_bundle(self, data):
        """
        The following get method is used to fetch the PreKeyBundle of user to create a pairwise signal session. The request must contain
        a boolean `is_sticky` to know whether this bundle would be used to communicate a SenderKey or not. If it will be used to
        communicate a SenderKey, then the PreKey must be marked as used, otherwise the PreKey is deleted from the server.
        """
        user_id = data['user_id']
        is_sticky = data['is_sticky']
        user = self.User.objects.get(id=user_id)
        identity_key = IdentityKey.objects.get(user=user, active=True)
        signed_pre_key = SignedPreKey.objects.get(user=user, active=True)
        pre_key = PreKey.objects.filter(user=user, used=False).first()
        PKB = {
            'identity_key': identity_key.public,
            'identity_key_id': identity_key.key_id,
            'user_id': user_id,
            'local_id': user.local_id,
            'signed_pre_key': signed_pre_key.public,
            'signed_pre_key_id': signed_pre_key.key_id,
            'signature': signed_pre_key.signature,
            'one_time_id': user.one_time_id,
        }
        if pre_key:
            PKB['pre_key'] = pre_key.public
            PKB['pre_key_id'] = pre_key.key_id
            if not is_sticky:
                pre_key.delete()
            else:
                pre_key.used = True
                pre_key.save()
        return PKB

    def get_pre_key_bundles(self, current_user, users_id):
        """
        Similar to the above method, but fetches PreKeyBundles of several users at once. This method allows a user to
        communicate their SenderKey to multiple members of a party at once.
        """
        bundles = {}
        # Make sure the current user is the first in the list. When creating DecryptionSenderKeys client-side to share
        # with other members - there must already be a corresponding EncryptionSenderKey.
        if current_user.id in users_id:
            users_id.remove(current_user.id)
            users_id.insert(0, current_user.id)

        to_be_removed = []
        for id in users_id:
            # If a non-existent user_id was provided, then their id must be removed from the list
            try:
                identity_key = IdentityKey.objects.get(user__id=id, active=True)
            except:
                to_be_removed.append(id)
                continue
            signed_pre_key = SignedPreKey.objects.get(user__id=id, active=True)
            pre_key = PreKey.objects.filter(user__id=id, used=False).first()
            user = self.User.objects.get(id=id)
            PKB = {
                'identity_key': identity_key.public,
                'identity_key_id': identity_key.key_id,
                'local_id': user.local_id,
                'user_id': id,
                'one_time_id': user.one_time_id,
                'signed_pre_key': signed_pre_key.public,
                'signed_pre_key_id': signed_pre_key.key_id,
                'signature': signed_pre_key.signature,
            }
            if pre_key:
                PKB['pre_key'] = pre_key.public
                PKB['pre_key_id'] = pre_key.key_id
                pre_key.used = True
                pre_key.save()
            bundles[id] = PKB
        for id in to_be_removed:
            users_id.remove(id)
        dict = {'bundles': bundles, 'users_id': users_id}
        return dict

    def get_sender_key(self, data, user):
        """
        This method is used to fetch the SenderKey of a stickySession.
        The body should contain the following fields:
            * stick_id - String
            * member_id - String
            * is_sticky - Boolean (are you fetching the SenderKey of a Sticky session or a standard session)
            * is_invitation - Boolean
        """
        member_id = data['member_id']
        stick_id = data['stick_id']
        is_invitation = False
        if 'is_invitation' in data:
            is_invitation = data['is_invitation']
        try:
            member = self.User.objects.get(id=member_id)
        except:
            member = self.User.objects.filter(one_time_id=member_id).first()
            if not member:
                return {'party_exists': False}

        # You need to check whether the user is authorized to fetch that SenderKey
        authorized = False
        party_exists = True
        if user in member.blocked.all():  # A blocked user is not authorized
            return {'authorized': authorized}
        if is_invitation:  # An invited user is authorized
            group = self.Group.objects.get(id=stick_id[:36])
            if group in user.invited_groups.all():
                authorized = True
        elif stick_id.startswith(user.parties.get(individual=False).id) or stick_id.startswith(user.parties.get(
                individual=True).id):  # A user is authorized to fetch SenderKeys of their own profile (user.party.id)
            authorized = True
        else:
            group_id = stick_id[:36]
            group = self.Group.objects.filter(id=group_id).first()
            if group:
                if group in user.groups.all():  # A group member is authorized
                    authorized = True
            else:
                party = Party.objects.filter(id=stick_id[:36]).first()
                if not party:
                    return {'party_exists': False}
                # A user connected with another user should be authorized
                if party.user and user in party.user.connections.all():
                    authorized = True
                else:
                    if user in party.connections.all():  # A user in the connections list of a party should be authorized
                        authorized = True
                    else:
                        user_groups = user.groups.all()
                        for group in party.groups.all():
                            if group in user_groups:  # If a Party and a User have a mutual Group, then that user is authorized
                                authorized = True
                                break
        if not authorized:  # if NOT authorized, return 401
            return {'authorized': authorized}

        if member_id != user.id:  # Trying to fetch DSK
            sender_key = DecryptionSenderKey.objects.filter(stick_id=stick_id, of_user=member_id,
                                                           for_user=user).first()
        else:  # Trying to fetch ESK
            party_id = stick_id[:36]
            chain_id = stick_id[36:]
            sender_key = EncryptionSenderKey.objects.filter(party_id=party_id, chain_id=chain_id, user=user).first()
        key = None
        phone = None
        if sender_key:  # If the SenderKey exists, we will return it
            if member_id != user.id:
                key = {'key': sender_key.key, 'identity_key_id': sender_key.identity_key.key_id}
            else:
                key = {'id': sender_key.key_id, 'key': sender_key.key, 'step': sender_key.step,
                       'identity_key_id': sender_key.identity_key.key_id}
        # SenderKey does not exist, send a `PendingKey` request to the target user to upload their key,
        # through a realtime database.
        else:
            if not PendingKey.objects.filter(user=user, stick_id=stick_id).exists():
                PendingKey.objects.create(user=user, owner=member, stick_id=stick_id)
                phone = member.phone
        return {'authorized': authorized, 'sender_key': key, 'phone': phone, 'party_exists': party_exists}

    def get_standard_sender_keys(self, data, user, group):
        """
        This method is used to fetch the standard session sender keys of a group.
        """
        stick_id = data['stick_id']
        keys_to_fetch = data['keys_to_fetch']
        if group not in user.groups.all():
            return {'authorized': False}
        sender_keys = {}
        for id in keys_to_fetch:
            sender_key = DecryptionSenderKey.objects.filter(stick_id=stick_id, of_one_time_id=id,
                                                           for_one_time_id=user.one_time_id).first()
            key = None
            if sender_key:
                key = sender_key.key
                sender_key.key = ''
                sender_key.save()
            sender_keys[id] = key
        return {'authorized': True, 'sender_keys': sender_keys}

    def get_stick_id(self, data, user):
        groups_ids = data['groups_ids']
        connections_ids = data['connections_ids']
        is_sticky = data['is_sticky']
        is_profile = False
        if 'is_profile' in data:
            is_profile = data['is_profile']
        if not is_profile and 'party_id' not in data:
            if len(groups_ids) == 1 and len(connections_ids) == 0:  # Sharing with a single group
                if is_sticky:  # Using sticky session
                    members_ids = self.Group.objects.get(id=groups_ids[0]).get_members_ids()
                    party_id = groups_ids[0]
                else:  # Using standard session
                    members_ids = self.Group.objects.get(id=groups_ids[0]).get_members_otids()
                    party_id = data['stick_id']
            else:  # Sharing with a collection of groups and/or users
                if len(connections_ids) > 0 and user.id not in connections_ids:
                    connections_ids.append(user.id)
                groups_ids.sort()
                connections_ids.sort()
                ids = ''.join(groups_ids + connections_ids)
                h = hashlib.sha256()
                h.update(ids.encode())
                party_hash = h.hexdigest() # party_hash is used for faster DB querying
                party = Party.objects.filter(party_hash=party_hash).first()
                if party == None:  # Create a new Party object if does not exist
                    party = Party.objects.create(party_hash=party_hash)
                    party.groups.set(groups_ids)
                    party.connections.set(connections_ids)
                members_ids = self.__create_targets(user, groups_ids, connections_ids)
                party_id = party.id
        elif 'party_id' in data:
            members_ids = [user.id]
            if data['type'] != 'group':
                party = Party.objects.get(id=data['party_id'])
                if party.user:
                    members_ids += party.user.get_connections_ids()
                    if party.user.id != user.id:
                        members_ids.append(party.user.id)
                elif data['type'] != 'individual':
                    members_ids = self.__create_targets(user, groups_ids, connections_ids)
            party_id = data['party_id']
        else:  # Sharing to the current_user's party (current_users' profile)
            members_ids = connections_ids
            is_individual = data['type'] == 'individual'
            party_id = Party.objects.get(user=user, individual=is_individual).id
        dict = {}
        bundles_to_fetch = []
        response_dict = {}

        # Find the right stick_id
        chain_id = 0
        sender_keys = EncryptionSenderKey.objects.filter(party_id=party_id, user=user).order_by('-chain_id')
        if len(sender_keys) > 0:
            active_sender_key = sender_keys[0]
            if not is_sticky:  # A standard session is valid
                dict[user.id] = {'exists': True}
            elif active_sender_key.step < self.session_life_cycle:  # Check whether is sticky session has not expired
                chain_id = active_sender_key.chain_id
                dict[user.id] = {'exists': True}
                response_dict['step'] = active_sender_key.step
            else:  # Sticky session has expired, increment chain_id by 1
                chain_id = active_sender_key.chain_id + 1
                dict[user.id] = {'exists': False}
                if user.id not in members_ids:
                    bundles_to_fetch.append(user.id)
        else:
            dict[user.id] = {'exists': False}
        stick_id = str(party_id) + str(chain_id)

        if not is_sticky:
            stick_id = party_id

        for member_id in members_ids:  # loop of the target users and check if they have their SenderKey
            if is_sticky:
                if user.id != member_id:
                    sender_key = DecryptionSenderKey.objects.filter(stick_id=stick_id, of_user=user,
                                                                   for_user=member_id).first()
                else:
                    sender_key = EncryptionSenderKey.objects.filter(party_id=party_id, chain_id=chain_id,
                                                                   user=user).first()
            else:
                sender_key = DecryptionSenderKey.objects.filter(stick_id=stick_id, of_one_time_id=user.one_time_id,
                                                               for_one_time_id=member_id).first()
            if sender_key:
                response = {'exists': True}
            else:
                response = {'exists': False}
                bundles_to_fetch.append(member_id)
            dict[member_id] = response
        response_dict['stick_id'] = stick_id
        response_dict['party_id'] = party_id
        response_dict['members'] = dict
        if user.id in bundles_to_fetch:
            bundles_to_fetch.remove(user.id)
            bundles_to_fetch.insert(0, user.id)
        response_dict['bundles_to_fetch'] = bundles_to_fetch
        return response_dict

    def __create_targets(self, user, groups_ids, connections_ids):
        members_ids = []
        for group_id in groups_ids:
            group = self.Group.objects.get(id=group_id)
            for member_id in group.get_members_ids():
                if not member_id in members_ids:
                    members_ids.append(member_id)
        for connection_id in connections_ids:
            if not connection_id in members_ids:
                members_ids.append(connection_id)
        if user.id not in members_ids:
            members_ids.append(user.id)
        return members_ids

    def get_active_stick_id(self, data, current_user):
        """
        This method gets the active sticky session stick_id associated with a particular party_id that already exists, and
        its current step.
        """
        party_id = data['party_id']
        sender_keys = EncryptionSenderKey.objects.filter(party_id=party_id, user=current_user).order_by('-chain_id')
        active_sender_key = sender_keys[0]
        response_dict = {}
        if active_sender_key.step < self.session_life_cycle:
            chain_id = active_sender_key.chain_id
            response_dict['step'] = active_sender_key.step
        else:
            chain_id = active_sender_key.chain_id + 1
        response_dict['stick_id'] = str(party_id) + str(chain_id)
        return response_dict

    def process_sender_key(self, data, user):
        """
        This method is used to save a SenderKey of a sticky session for a user. Typically used when a user
        receives a `PendingKey` request.
        """
        pre_key = PreKey.objects.get(key_id=data['pre_key_id'], user__id=data['for_user'])
        for_user = self.User.objects.get(id=data['for_user'])
        identity_key = IdentityKey.objects.get(key_id=data['identity_key_id'], user__id=data['for_user'])
        decrypting_sender_key = DecryptionSenderKey.objects.create(key=data['key'],
                                                                 stick_id=data['stick_id'], of_user=user, for_user=for_user,
                                                                 pre_key=pre_key, identity_key=identity_key)
        decrypting_sender_key.save()

    def process_sender_keys(self, data, user):
        """
        This method is used to save SenderKeys of multiple users at once. Before making an upload, and after
        the user has made a request to get the UploadedSenderKeys, and now knows which users does not have SenderKeys for
        a particular sticky session, the user can upload those SenderKeys through this method.
        """
        users_id = data['users_id']
        keys = data['keys']
        for id in users_id:
            sender_key = keys[id]
            pre_key = PreKey.objects.get(key_id=sender_key['pre_key_id'], user__id=id)
            identity_key = IdentityKey.objects.get(key_id=sender_key['identity_key_id'], user__id=id)
            if id != user.id:  # Other user? Create a DSK
                for_user = self.User.objects.get(id=sender_key['for_user'])
                DecryptionSenderKey.objects.create(key=sender_key['key'],
                                                   stick_id=sender_key['stick_id'], of_user=user,
                                                   pre_key=pre_key, identity_key=identity_key, for_user=for_user)
            else:  # Current user? Create an ESK
                party_id = sender_key['stick_id'][:36]
                chain_id = sender_key['stick_id'][36:]
                EncryptionSenderKey.objects.create(key_id=sender_key['id'], pre_key=pre_key, identity_key=identity_key,
                                                   party_id=party_id, chain_id=chain_id,
                                                   user=user, key=sender_key['key'])

    def process_standard_sender_keys(self, data, user):
        """
        This method is used to upload the SenderKeys of a standard session.
        """
        stick_id = data['stick_id']
        keys_to_upload = data['keys_to_upload']
        for one_time_id, sender_key in keys_to_upload.items():
            DecryptionSenderKey.objects.create(key=sender_key, stick_id=stick_id, of_user=user,
                                               for_one_time_id=one_time_id, of_one_time_id=user.one_time_id)

    def update_active_spk(self, data, user):
        """
        This method is used to update the active signed prekey for a user
        """
        old_spk = SignedPreKey.objects.get(user=user, active=True)
        old_spk.active = False
        old_spk.save()
        SignedPreKey.objects.create(user=user, public=data['public'], signature=data['signature'],
                                    key_id=data['id'], cipher=data['cipher'], salt=data['salt'],
                                    timestamp=data['timestamp'], active=True)

    def update_active_ik(self, data, user):
        """
        This method is used to update the active identity key for a user
        """
        old_ik = IdentityKey.objects.get(user=user, active=True)
        old_ik.active = False
        old_ik.save()
        IdentityKey.objects.create(user=user, public=data['public'],
                                   key_id=data['id'], cipher=data['cipher'], salt=data['salt'],
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
        if user.check_password(data['password_hash']):  # This will create a "double-hash" and verify it
            signed_pre_keys_list = SignedPreKey.objects.filter(user=user)
            identity_keys_list = IdentityKey.objects.filter(user=user)
            pre_keys_list = PreKey.objects.filter(user=user).order_by('-dt_timestamp')
            sender_keys_list = EncryptionSenderKey.objects.filter(user=user)
            bundle = {'local_id': user.local_id}
            identity_keys = []
            for ik in identity_keys_list:
                key = {'id': ik.key_id, 'public': ik.public, 'cipher': ik.cipher, 'salt': ik.salt, 'active': ik.active,
                       'timestamp': ik.timestamp}
                identity_keys.append(key)
            bundle['identity_keys'] = identity_keys
            signed_pre_keys = []
            for spk in signed_pre_keys_list:
                key = {'id': spk.key_id, 'public': spk.public, 'cipher': spk.cipher, 'salt': spk.salt,
                       'signature': spk.signature, 'active': spk.active, 'timestamp': spk.timestamp}
                signed_pre_keys.append(key)
            bundle['signed_pre_keys'] = signed_pre_keys
            pre_keys = []
            for pre_key in pre_keys_list:
                key = {'id': pre_key.key_id, 'public': pre_key.public, 'cipher': pre_key.cipher, 'salt': pre_key.salt,
                       'used': pre_key.used}
                pre_keys.append(key)
            bundle['pre_keys'] = pre_keys
            sender_keys = []
            for sender_key in sender_keys_list:
                stick_id = sender_key.party_id + str(sender_key.chain_id)
                key = {'id': sender_key.key_id, 'key': sender_key.key, 'stick_id': stick_id, 'step': sender_key.step,
                       'identity_key_id': sender_key.identity_key.key_id, 'pre_key_id': sender_key.pre_key.key_id}
                sender_keys.append(key)
            bundle['sender_keys'] = sender_keys
            user.save()
            device = self.Device.objects.filter(user=user, device_id=data['device_id']).first()
            if not device:
                device = self.Device.objects.create(user=user, device_id=data['device_id'], name=data['device_name'], chat_id=uuid.uuid4())
            else:
                device.chat_id = uuid.uuid4()
            bundle['one_time_id'] = device.chat_id
            return {'bundle': bundle, 'verify': True}
        else:
            return {'verify': False}

    def process_reencrypted_keys(self, data, user):
        """
        A method to process reencrypted keys for when changing the user's password
        """
        success = False
        if user.check_password(data['current_pass']):
            for key in data['pre_keys']:
                pre_key = PreKey.objects.filter(key_id=key['id'], user=user).first()
                if pre_key:
                    pre_key.cipher = key['cipher']
                    pre_key.salt = key['salt']
                    pre_key.save()
            for key in data['signed_pre_keys']:
                spk = SignedPreKey.objects.get(key_id=key['id'], user=user)
                spk.cipher = key['cipher']
                spk.salt = key['salt']
                spk.save()
            for key in data['identity_keys']:
                ik = IdentityKey.objects.get(key_id=key['id'], user=user)
                ik.cipher = key['cipher']
                ik.salt = key['salt']
                ik.save()
            user.password_salt = data['new_salt']
            user.set_password(data['new_pass'])
            user.save()
            success = True
        return {'success': success}
