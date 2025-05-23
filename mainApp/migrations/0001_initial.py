# Generated by Django 5.0.3 on 2025-03-07 09:57

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AdminCredentials',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=100)),
                ('salt', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='Sheets',
            fields=[
                ('ObsDateTime', models.AutoField(primary_key=True, serialize=False)),
                ('Height', models.CharField(max_length=100)),
                ('Windspeed', models.CharField(max_length=100)),
                ('WindDirection', models.CharField(max_length=100)),
                ('Temperature', models.CharField(max_length=100)),
                ('Pressure', models.CharField(max_length=100)),
                ('Humidity', models.CharField(max_length=100)),
                ('Date', models.DateField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=100)),
                ('phone', models.CharField(max_length=100)),
                ('department', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='UserCredentials',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=100)),
                ('salt', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('report', models.FileField(upload_to='report/')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='mainApp.user')),
            ],
        ),
    ]
