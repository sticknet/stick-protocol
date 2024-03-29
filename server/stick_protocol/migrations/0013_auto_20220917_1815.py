# Generated by Django 3.1.5 on 2022-09-17 14:15

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('stick_protocol', '0012_auto_20220917_1802'),
    ]

    operations = [
        migrations.AlterField(
            model_name='decryptionsenderkey',
            name='for_user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='received_sender_keys', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='decryptionsenderkey',
            name='of_user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='decrypting_sender_keys', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='encryptionsenderkey',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='encrypting_sender_keys', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='identitykey',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='identity_keys', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='pendingkey',
            name='owner',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pending_keys', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='pendingkey',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_pending_keys', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='prekey',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pre_keys', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='signedprekey',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='signed_pre_keys', to=settings.AUTH_USER_MODEL),
        ),
    ]
