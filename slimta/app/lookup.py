# Copyright (c) 2014 Ian C. Good
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

from passlib import apps

from .validation import ConfigValidationError


def _load_redis_lookup(options):
    from slimta.lookup.drivers.redis import RedisLookup
    if 'key_template' not in options:
        msg = 'redis lookup requires key_template option'
        raise ConfigValidationError(msg)
    kwargs = {'key_template': options.key_template}
    if 'host' in options:
        kwargs['host'] = options.host
    if 'port' in options:
        kwargs['port'] = int(options.port)
    if 'db' in options:
        kwargs['db'] = int(options.db)
    if 'password' in options:
        kwargs['password'] = options.password
    if 'socket_timeout' in options:
        kwargs['socket_timeout'] = float(options.socket_timeout)
    if 'use_hash' in options:
        kwargs['use_hash'] = options.use_hash
    return RedisLookup(**kwargs)


def _load_sqlite3_lookup(options):
    from slimta.lookup.drivers.dbapi2 import SQLite3Lookup
    for opt in ['database', 'query']:
        if opt not in options:
            msg = 'sqlite3 lookup requires {0} option'.format(opt)
            raise ConfigValidationError(msg)
    return SQLite3Lookup(opt.database, opt.query)


def _load_dict_lookup(options):
    from slimta.lookup.drivers.dict import DictLookup
    if 'map' not in options:
        msg = 'config lookup requires map section'
        raise ConfigValidationError(msg)
    key_template = options.get('key_template', '{address}')
    return DictLookup(options.map, key_template)


def load_lookup(options):
    if not options:
        return
    if options.type == 'redis':
        return _load_redis_lookup(options)
    elif options.type == 'sqlite3':
        return _load_sqlite3_lookup(options)
    elif options.type == 'config':
        return _load_dict_lookup(options)
    else:
        msg = 'lookup type does not exist: '+options.type
        raise ConfigValidationError(msg)


def get_hash_context(name):
    if not name:
        return apps.ldap_context
    else:
        return getattr(apps, name + '_context')


# vim:et:fdm=marker:sts=4:sw=4:ts=4
