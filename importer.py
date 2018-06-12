#!/usr/bin/env python2

from flask import Flask
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import OperationalError
from werkzeug.datastructures import FileStorage
from CTFd import utils

import yaml

import argparse
import hashlib
import os
import sys

REQ_FIELDS = ['name', 'description', 'value', 'category', 'flags']


def parse_args():
    parser = argparse.ArgumentParser(description='Import CTFd challenges and their attachments to a DB from a YAML formated specification file and an associated attachment directory')
    parser.add_argument('--app-root', dest='app_root', type=str, help="app_root directory for the CTFd Flask app (default: 2 directories up from this script)", default=None)
    parser.add_argument('-d', dest='db_uri', type=str, help="URI of the database where the challenges should be stored")
    parser.add_argument('-F', dest='dst_attachments', type=str, help="directory where challenge attachment files should be stored")
    parser.add_argument('-i', dest='in_file', type=str, help="name of the input YAML file (default: export.yaml)", default="export.yaml")
    parser.add_argument('--skip-on-error', dest="exit_on_error", action='store_false', help="If set, the importer will skip the importing challenges which have errors rather than halt.", default=True)
    parser.add_argument('--move', dest="move", action='store_true', help="if set the import proccess will move files rather than copy them", default=False)
    return parser.parse_args()


def process_args(args):
    if not (args.db_uri and args.dst_attachments):
        if args.app_root:
            app.root_path = os.path.abspath(args.app_root)
        else:
            abs_filepath = os.path.abspath(__file__)
            grandparent_dir = os.path.dirname(os.path.dirname(os.path.dirname(abs_filepath)))
            app.root_path = grandparent_dir
        sys.path.append(os.path.dirname(app.root_path))
        app.config.from_object("CTFd.config.Config")

    if args.db_uri:
        app.config['SQLALCHEMY_DATABASE_URI'] = args.db_uri
    if not args.dst_attachments:
        args.dst_attachments = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])

    return args


class MissingFieldError(Exception):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return "Missing field '{}'".format(self.name)


def validate_yaml(chal):
    """Ensure all required fields are present."""

    for req_field in REQ_FIELDS:
        if req_field not in chal:
            raise MissingFieldError(req_field)

    chal['name'] = chal['name'].strip()
    chal['description'] = chal['description'].strip()
    chal['category'] = chal['category'].strip()

    # Set defaults for optional types
    if 'type' in chal:
        chal['type'] = chal['type'].strip()
    else:
        chal['type'] = 'standard'

    if 'tags' not in chal:
        chal['tags'] = []
    if 'files' not in chal:
        chal['files'] = []
    if 'hidden' not in chal:
        chal['hidden'] = False

    for flag in chal['flags']:
        if 'flag' not in flag:
            raise MissingFieldError('flag')
        flag['flag'] = flag['flag'].strip()
        if 'type' not in flag:
            flag['type'] = 'static'


def import_challenges(in_file, dst_attachments, exit_on_error=True, move=False):
    from CTFd.models import db, Challenges, Keys, Tags, Files
    with open(in_file, 'r') as in_stream:
        chals = yaml.safe_load_all(in_stream)

        for chal in chals:
            # ensure all required fields are present before adding or updating a challenge
            try:
                validate_yaml(chal)
            except MissingFieldError as err:
                if exit_on_error:
                    raise
                else:
                    print "Skipping challenge: " + str(err)
                    continue

            # if the challenge already exists, update it
            chal_db = Challenges.query.filter_by(name=chal['name']).first()
            if chal_db is not None:
                print "Updating {}".format(chal['name'].encode('utf8'))
                chal_db.description = chal['description']
                chal_db.value = chal['value']
                chal_db.category = chal['category']
            else:
                print "Adding {}".format(chal['name'].encode('utf8'))
                chal_db = Challenges(
                    chal['name'],
                    chal['description'],
                    chal['value'],
                    chal['category'])
            chal_db.type = chal['type']
            chal_db.hidden = chal['hidden']

            db.session.add(chal_db)
            db.session.commit()

            # delete all tags and re-add them
            Tags.query.filter_by(chal=chal_db.id).delete()
            for tag in chal['tags']:
                tag_dbobj = Tags(chal_db.id, tag)
                db.session.add(tag_dbobj)

            # delete all flags and re-add them
            Keys.query.filter_by(chal=chal_db.id).delete()
            for flag in chal['flags']:
                flag_db = Keys(chal_db.id, flag['flag'], flag['type'])
                db.session.add(flag_db)

            # hash and compare existing files with the new uploaded files
            hashes_db = {}
            files_db = Files.query.filter_by(chal=chal_db.id).all()
            for file_db in files_db:
                with open(os.path.join(dst_attachments, file_db.location), 'rb') as f:
                    h = hashlib.md5(f.read()).digest()
                    hashes_db[h] = file_db

            to_upload = []
            for file in chal['files']:
                path = os.path.join(os.path.dirname(in_file), file)
                with open(path, "rb") as f:
                    h = hashlib.md5(f.read()).digest()
                if h in hashes_db and os.path.basename(file) == os.path.basename(hashes_db[h].location):
                    # the file is up to date
                    del hashes_db[h]
                else:
                    # the file has changed name or content
                    to_upload.append(path)

            # remove out of date files and add new uploads
            for file_db in hashes_db.values():
                print "  Removing file {}".format(file_db.location)
                utils.delete_file(file_db.id)
            for path in to_upload:
                basename = os.path.basename(path)
                print "  Adding file {}".format(basename)
                with open(path, "rb") as f:
                    f = FileStorage(stream=f, filename=basename)
                    utils.upload_file(file=f, chalid=chal_db.id)
                if move:
                    os.unlink(path)

            db.session.commit()

    db.session.commit()
    db.session.close()


if __name__ == "__main__":
    args = parse_args()

    app = Flask(__name__)

    with app.app_context():
        args = process_args(args)
        from CTFd.models import db

        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        url = make_url(app.config['SQLALCHEMY_DATABASE_URI'])
        if url.drivername == 'postgres':
            url.drivername = 'postgresql'

        db.init_app(app)

        try:
            if not (url.drivername.startswith('sqlite') or database_exists(url)):
                create_database(url)
            db.create_all()
        except OperationalError:
            db.create_all()
        else:
            db.create_all()

        app.db = db
        import_challenges(args.in_file, args.dst_attachments, args.exit_on_error, move=args.move)
