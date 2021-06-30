#   Copyright © 2018-2021 STiiiCK.
#
#   This source code is licensed under the GPLv3 license found in the
#   LICENSE file in the root directory of this source tree.

from django.contrib import admin

from .models import IdentityKey, SignedPreKey, PreKey, EncryptionSenderKey, DecryptionSenderKey, Party, PendingKey

admin.site.register(IdentityKey)
admin.site.register(SignedPreKey)
admin.site.register(PreKey)
admin.site.register(EncryptionSenderKey)
admin.site.register(DecryptionSenderKey)
admin.site.register(Party)
admin.site.register(PendingKey)