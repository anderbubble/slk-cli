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

    subparsers = argparser.add_subparsers(title='subcommands')

    version = subparsers.add_parser('version')
    version.set_defaults(func=get_version)

    exports = subparsers.add_parser('exports')
    exports.set_defaults(func=get_exports)

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
    if args.func:
        args.func(
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
        print(record['_id'], record['name'])


if __name__ == '__main__':
    main()
