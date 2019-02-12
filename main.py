#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Sample Script
    Version 0.2.1
"""

import logging
import json
import os
import sys

from google.oauth2 import id_token
from google.auth.transport import requests
from flask import Flask, redirect, render_template, request, session, url_for
import ldap3
from ldap3 import Server, Connection, ALL

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
log = logging.getLogger(__file__)


def get_config(file_path: str):
    config = {}
    with open(file_path, 'r') as f:
        loaded_config = json.load(f)
        config.update(loaded_config)
    return config


def create_app():
    tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    app = Flask(__name__, template_folder=tmpl_dir)
    app.config.from_mapping(SECRET_KEY=os.environ.get('SECRET_KEY') or 'dev_key')

    return app


def search_ldap():
    attributes = [cfg['attributes'][k] for k in cfg['attributes'].keys() if cfg['attributes'][k]]

    server = Server(cfg['server'], port=cfg['port'], get_info=ALL)
    conn = Connection(server, cfg['binddn'], cfg['secret'], auto_bind=True)
    conn.search(
        search_base=",".join([cfg['usersearchbase'], cfg['basedn']]),
        search_filter="(&(objectclass={})({}))".format(cfg['objectclass'], cfg['userobjectfilter']),
        attributes=attributes)

    users = [json.loads(e.entry_to_json())['attributes'] for e in conn.entries]

    flat_users = []
    for user in users:
        for key in user.keys():
            user[key] = user[key][0] if user[key] else ""
        flat_users.append(user)
    return flat_users


cfg = get_config('config.json')
CLIENT_ID = cfg['auth']['client_id']
GSUITE_DOMAIN_NAME = cfg['auth']['gsuit_domain_name']
app = create_app()


def remap_ldap_attributes(user: dict):
    remapped = {}
    for attr in cfg['attributes'].keys():
        remapped[attr] = user[cfg['attributes'][attr]] if cfg['attributes'][attr] in user else ""

    return remapped


@app.route('/', methods=['GET'])
def index():
    if 'idinfo' not in session:
        return redirect(url_for('permission_denied'))

    try:
        users = search_ldap()
        users = sorted([remap_ldap_attributes(u) for u in users], key=lambda k: k['sureName'])
        return render_template('people.html', users=users, idinfo=session['idinfo'])
    except ldap3.core.exceptions.LDAPException as e:
        return render_template('people.html', error_msg=str(e), idinfo=session['idinfo'])


@app.route('/profile', methods=['GET'])
def profile():
    if 'idinfo' not in session:
        return redirect(url_for('permission_denied'))

    return render_template('profile.html', idinfo=session['idinfo'])


@app.route('/401', methods=['GET'])
def permission_denied():
    return render_template('401.html'), 401


@app.route('/_auth', methods=['POST'])
def authenticate_with_google_token():
    token = request.form['idtoken']

    try:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)

        log.info("%s logged in, issued by %s from domain %s", idinfo['sub'], idinfo['iss'], idinfo['hd'])

        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')

        # If auth request is from a G Suite domain:
        if idinfo['hd'] != GSUITE_DOMAIN_NAME:
            raise ValueError('Wrong hosted domain.')

        # Save auth information in session
        session['idinfo'] = idinfo

        return redirect(url_for('index'))
    except ValueError:
        log.info("invalid token: %s", token)
        # Invalid token
        return redirect(url_for('permission_denied'))


if __name__ == '__main__':
    app.run()