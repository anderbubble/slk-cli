#!/usr/bin/env python


from __future__ import print_function


import argparse
import ConfigParser
import os
import pprint
import requests
import requests.status_codes
import urllib3


def main ():
    argparser = get_argparser()
    config = get_config()

    args = argparser.parse_args()

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    kwargs = {
        'url': config.get('api', 'url'),
        'verify': config.getboolean('api', 'verify'),
    }

    if args.authenticate:
        kwargs['session_key'] = authenticate(
            domain = config.get('api', 'domain'),
            username = config.get('api', 'username'),
            password = config.get('api', 'password'),
            **kwargs
        )

    kwargs['version'] = config.get('api', 'version')

    if args.path == 'version':
        for record in get_version(
                url = config.get('api', 'url'),
                verify = config.getboolean('api', 'verify'),
        ):
            print_record(record, path=args.path, dsv=args.dsv, pprint_=args.pprint)
    elif args.delete:
        response = delete_dynamic(args.path, **kwargs)
        print(response.status_code, requests.status_codes._codes[response.status_code][0])
    else:
        for record in get_records_dynamic(args.path, **kwargs):
            print_record(record, path=args.path, dsv=args.dsv, pprint_=args.pprint)


def get_argparser ():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--authenticate', action='store_true', default=False)
    argparser.add_argument('--pprint', action='store_true', default=False)
    argparser.add_argument('--dsv', action='store_true', default=False)
    argparser.add_argument('--delete', action='store_true', default=False)
    argparser.add_argument('path')
    return argparser


def get_config ():
    config = ConfigParser.SafeConfigParser()
    config.read([os.path.expanduser('~/.slk-api.cfg')])
    return config


def get_version (url, verify=True):
    response = requests.get('{url}/version'.format(url=url), verify=verify)
    return response.json()['records']


def authenticate (url, domain, username, password, verify=True):
    response = requests.post('{url}/auth'.format(url=url), verify=verify,
                             json={
                                 'domain':domain,
                                 'name':username,
                                 'password':password,
                                 })
    session_key = response.json()['records'][0]['sessionKey']
    return session_key


def get_records_dynamic (path, url, version, session_key=None, verify=True):
    headers = {}
    if session_key is not None:
        headers['X-SDS-SessionKey'] = session_key
    print(headers)
    response = requests.get('/'.join((url, version, path)), verify=verify, headers=headers)
    check_errors(response.json())
    return response.json()['records']


def delete_dynamic (path, url, version, session_key=None, verify=True):
    headers = {}
    if session_key is not None:
        headers['X-SDS-SessionKey'] = session_key
    response = requests.delete('/'.join((url, version, path)), verify=verify, headers=headers)
    return response


def check_errors (response_dict):
    if 'errors' in response_dict:
        raise RESTErrors(response_dict)


SIMPLE_FIELDS = {
    'version': ('version', ),
    'stores': ('storeID', 'storeType', 'name', 'url', 'description'),
    'pools': ('_id', 'name', 'description'),
    'namespaces': ('_id', 'posix_uid', 'posix_gid', 'posix_mode', 'path'),
    'exports': ('_id', 'name', 'description', 'nsID'),
    'users': ('_id', 'name'),
    'roles': ('description', ),
}
SIMPLE_FIELDS['special'] = SIMPLE_FIELDS['users']
SIMPLE_FIELDS['whoami'] = SIMPLE_FIELDS['users']


def get_record_type_from_path (path):
    for element in reversed(path.split('/')):
        if element in SIMPLE_FIELDS:
            return element
    else:
        raise NotImplementedError(path)


def print_record (record, path=None, dsv=False, pprint_=False):
    if dsv:
        if path is None:
            raise TypeParseError('unable to determine record type without path')
        record_type = get_record_type_from_path(path)
        print(simple_dsv(record, record_type))
    elif pprint_:
        pprint.pprint(record)
    else:
        print(record)


def simple_dsv (record, type_):
    try:
        fields = SIMPLE_FIELDS[type_]
    except KeyError:
        raise NotImplementedError(type_)
    return '|'.join(str(record[f]) for f in fields)


class RESTErrors (Exception): pass


class TypeParseError (Exception): pass


if __name__ == '__main__':
    main()
