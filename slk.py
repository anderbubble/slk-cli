#!/usr/bin/env python


from __future__ import print_function


import argparse
import ConfigParser
import os
import pprint
import requests
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

    pkwargs = {
        'type_': args.subcommand,
        'pprint_': args.pprint,
        'dsv': args.dsv,
    }

    authd_kwargs = kwargs.copy()

    if args.authenticate:
        authd_kwargs['session_key'] = authenticate(
            domain = config.get('api', 'domain'),
            username = config.get('api', 'username'),
            password = config.get('api', 'password'),
            **kwargs
        )

    if args.subcommand == 'version':
        print(get_version(**kwargs))

    elif args.subcommand in ('stores', 'pools', 'exports'):
        for id_ in args.ids:
            for record in get_simple_by_id(args.subcommand, id_, **authd_kwargs):
                print_record(record, **pkwargs)
        if not args.ids:
            for record in get_simple(args.subcommand, **authd_kwargs):
                print_record(record, **pkwargs)

    elif args.subcommand == 'namespaces':
        for id_ in args.ids:
            for record in get_simple_by_id('namespaces', id_, **authd_kwargs):
                print_record(record, **pkwargs)
        if not args.ids:
            for record in get_namespaces(**authd_kwargs):
                print_record(record, **pkwargs)

    elif args.subcommand == 'exports':
        for record in get_simple('exports', **authd_kwargs):
            print_record(record, **pkwargs)

    else:
        raise NotImplementedError(args.subcommand)


def get_argparser ():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--authenticate', action='store_true', default=False)
    argparser.add_argument('--pprint', action='store_true', default=False)
    argparser.add_argument('--dsv', action='store_true', default=False)

    subparsers = argparser.add_subparsers(title='subcommands', dest='subcommand')

    version = subparsers.add_parser('version')

    stores = subparsers.add_parser('stores')
    stores.add_argument('ids', nargs='*')

    pools = subparsers.add_parser('pools')
    pools.add_argument('ids', nargs='*')

    namespaces = subparsers.add_parser('namespaces')
    namespaces.add_argument('ids', nargs='*')

    exports = subparsers.add_parser('exports')
    exports.add_argument('ids', nargs='*')
    return argparser


def get_config ():
    config = ConfigParser.SafeConfigParser()
    config.read([os.path.expanduser('~/.slk-api.cfg')])
    return config


def get_version (url, verify=True):
    response = requests.get('{url}/version'.format(url=url), verify=verify)
    version = response.json()['records'][0]['version']
    return version


def authenticate (url, domain, username, password, verify=True):
    response = requests.post('{url}/auth'.format(url=url), verify=verify,
                             json={
                                 'domain':domain,
                                 'name':username,
                                 'password':password,
                                 })
    session_key = response.json()['records'][0]['sessionKey']
    return session_key


def get_simple (model, url, session_key=None, verify=True):
    response = requests.get('{url}/v1/{model}'.format(url=url, model=model), verify=verify, headers={'X-SDS-SessionKey': session_key})
    check_errors(response.json())
    return response.json()['records']


def check_errors (response_dict):
    if 'errors' in response_dict:
        raise RESTErrors(*response_dict['errors'])


def get_simple_by_id (model, id_, url, session_key, verify=True):
    response = requests.get('{url}/v1/{model}/{id_}'.format(url=url, model=model, id_=id_), verify=verify, headers={'X-SDS-SessionKey': session_key})
    return response.json()['records']


def get_namespaces (url, model, session_key=None, verify=True, parent_id="1", names=['pl'], attributes={}):
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


SIMPLE_FIELDS = {
    'stores': ('storeID', 'storeType', 'name', 'url', 'description'),
    'pools': ('_id', 'name', 'description'),
    'namespaces': ('_id', 'posix_uid', 'posix_gid', 'posix_mode', 'path'),
    'exports': ('_id', 'name', 'description', 'nsID'),
}


def print_record (record, type_, dsv=False, pprint_=False):
    if dsv:
        try:
            fields = SIMPLE_FIELDS[type_]
        except KeyError:
            raise NotImplementedError(type_)
        print(simple_dsv(record, fields))
    elif pprint_:
        pprint.pprint(record)
    else:
        print(record)


def simple_dsv (record, fields):
    return '|'.join(str(record[f]) for f in fields)


class RESTErrors (Exception): pass


if __name__ == '__main__':
    main()
