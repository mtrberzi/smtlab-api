#!/usr/bin/env python

import getpass
from app import models, db, app
from app.models import PermissionEnum
import sys
import flask_migrate
import boto3
from botocore.exceptions import ClientError

admin_perms = [PermissionEnum.read, PermissionEnum.upload_benchmark, PermissionEnum.upload_solver, PermissionEnum.start_run, PermissionEnum.change_password, PermissionEnum.change_other_password, PermissionEnum.admin_user]

def create_database():
    print("Creating and upgrading database.")
    flask_migrate.upgrade()

def create_first_admin_user():
    has_admin = False
    users = models.User.query.all()
    for user in users:
        if user.has_permission(PermissionEnum.admin_user):
            has_admin = True
            break
    if has_admin:
        print("Admin user already exists.")
        return
    print("Creating admin user.")
    while True:
        print("Enter username: ", end='')
        sys.stdout.flush()
        admin_username = sys.stdin.readline().strip()
        user = models.User.query.filter_by(username=admin_username).first()
        if user is not None:
            print("That user already exists.")
        else:
            break
    while True:
        admin_password = getpass.getpass(prompt="Enter a new password for the admin user: ")
        confirm_password = getpass.getpass(prompt="Confirm password: ")
        if admin_password != confirm_password:
            print("Passwords do not match.")
        else:
            break
    user = models.User(username=admin_username)
    user.hash_password(admin_password)

    for perm in admin_perms:
        user.permissions.append(models.Permission(permission=perm))
    db.session.add(user)
    db.session.commit()

def create_queues():
    queues = ['scheduler', 'regression', 'performance']
    client = boto3.resource('sqs', endpoint_url=app.config['QUEUE_URL'], region_name='elasticmq', aws_access_key_id='x', aws_secret_access_key='x', use_ssl=False)
    for queue in queues:
        print(f"Creating queue {queue}.")
        try:
            client.create_queue(QueueName=queue)
        except ClientError as e:
            if e['Error']['Code'] == 'QueueAlreadyExists':
                pass
            else:
                raise e

def main():
    app.app_context().push()
    create_database()
    create_first_admin_user()
    create_queues()

if __name__ == '__main__':
    main()
