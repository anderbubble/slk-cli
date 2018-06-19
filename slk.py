#!/usr/bin/env python


from __future__ import print_function


import argparse
import ConfigParser
import os
import requests
import urllib3


def main ():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--authenticate', action='store_true', default=False)

    subparsers = argparser.add_subparsers(title='subcommands', dest='subcommand')

    version = subparsers.add_parser('version')

    exports = subparsers.add_parser('exports')

    namespaces = subparsers.add_parser('namespaces')
    namespaces.add_argument('ids', nargs='*')
    namespaces.add_argument('--detail', action='store_true', default=False)
    namespaces.add_argument('--json', action='store_true', default=False)

    config = ConfigParser.SafeConfigParser()
    config.read([os.path.expanduser('~/.slk-api.cfg')])

    args = argparser.parse_args()

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.authenticate:
        session_key = authenticate(
            url = config.get('api', 'url'),
            verify = config.getboolean('api', 'verify'),
            domain = config.get('api', 'domain'),
            username = config.get('api', 'username'),
            password = config.get('api', 'password'),
        )
    else:
        session_key = None

    if args.subcommand == 'version':
        get_version(
            url=config.get('api', 'url'),
            verify=config.getboolean('api', 'verify'),
        )
    elif args.subcommand == 'namespaces':
        if not args.ids:
            get_namespaces(
                session_key = session_key,
                url=config.get('api', 'url'),
                verify=config.getboolean('api', 'verify'),
            )
        for id_ in args.ids:
            for record in get_namespace(
                    session_key = session_key,
                    id_ = id_,
                    url=config.get('api', 'url'),
                    verify=config.getboolean('api', 'verify'),
            ):
                print_namespace(record, detail=args.detail, json=args.json)
    elif args.subcommand == 'exports':
        get_exports(
            session_key = session_key,
            url=config.get('api', 'url'),
            verify=config.getboolean('api', 'verify'),
        )


def get_version (url, verify=True):
    response = requests.get('{url}/version'.format(url=url), verify=verify)
    version = response.json()['records'][0]['version']
    print(version)


def authenticate (url, domain, username, password, verify=True):
    response = requests.post('{url}/auth'.format(url=url), verify=verify,
                             json={
                                 'domain':domain,
                                 'name':username,
                                 'password':password,
                                 })
    session_key = response.json()['records'][0]['sessionKey']
    return session_key


def get_exports (url, session_key, verify=True):
    response = requests.get('{url}/v1/exports'.format(url=url), verify=verify, headers={'X-SDS-SessionKey': session_key})
    for record in response.json()['records']:
        namespace = list(get_namespace(url, session_key, record['nsID'], verify=verify))[0]
        print(record['_id'], record['attributes']['mountType'], record['attributes']['mountOptions'], record['attributes']['mountHosts'], record['name'], namespace['path'])


def get_namespaces (url, session_key, verify=True, parent_id="1", names=['pl'], attributes={}):
    response = requests.get('{url}/v1/namespaces'.format(url=url),
                            verify=verify,
                            headers={'X-SDS-SessionKey': session_key},
                            json={'namespaces':{
                                'parent_id':parent_id,
                                'names': names,
                                'attributes': attributes,
                            }})
    print(response.json())
    for record in response.json()['records']:
        print(record)


def get_namespace (url, session_key, id_, verify=True):
    response = requests.get('{url}/v1/namespaces/{id_}'.format(url=url, id_=id_), verify=verify, headers={'X-SDS-SessionKey': session_key})
    for record in response.json()['records']:
        yield record


def print_namespace (record, detail=False, json=False):
    if json:
        print(record)
    elif detail:
        print(record['path'])
        print('    parent: {}'.format(record['parent_id']))
    else:
        print(record['path'])

if __name__ == '__main__':
    main()
