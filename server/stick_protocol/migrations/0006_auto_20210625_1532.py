# Generated by Django 3.1.5 on 2021-06-25 11:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('stick_protocol', '0005_party_timestamp'),
    ]

    operations = [
        migrations.AlterField(
            model_name='party',
            name='partyHash',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
    ]