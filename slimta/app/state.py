# Copyright (c) 2013 Ian C. Good
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

from __future__ import absolute_import

import sys
import os
import os.path
import warnings
import logging
from importlib import import_module
from functools import wraps
from contextlib import contextmanager
from weakref import WeakValueDictionary

from config import Config, ConfigError, ConfigInputStream
from gevent import sleep, socket
import slimta.system

from .validation import ConfigValidation, ConfigValidationError
from .logging import setup_logging


class SlimtaState(object):

    _global_config_files = [os.path.expanduser('~/.slimta/slimta.conf'),
                            '/etc/slimta/slimta.conf']

    def __init__(self, args):
        self.program = os.path.basename(sys.argv[0])
        self.args = args
        self.cfg = None
        self.listeners = WeakValueDictionary()
        self.edges = {}
        self.queues = {}
        self.relays = {}
        self._celery = None

    @contextmanager
    def _with_chdir(self, new_dir):
        old_dir = os.getcwd()
        os.chdir(new_dir)
        try:
            yield old_dir
        finally:
            os.chdir(old_dir)

    @contextmanager
    def _with_sighandlers(self):
        from signal import SIGTERM
        from gevent import signal
        def handle_term():
            sys.exit(0)
        old_term = signal(SIGTERM, handle_term)
        try:
            yield
        finally:
            signal(SIGTERM, old_term)

    def _try_configs(self, files):
        for config_file in files:
            config_file = os.path.expanduser(config_file)
            config_dir = os.path.abspath(os.path.dirname(config_file))
            config_base = os.path.basename(config_file)
            if os.path.isdir(config_dir):
                with self._with_chdir(config_dir):
                    if os.path.exists(config_base):
                        return Config(config_base), config_file
        return None, None

    def load_config(self, argparser=None):
        if self.args.process_name:
            self.program = self.args.process_name

        files = self._global_config_files
        if self.args.config:
            files = [self.args.config]

        self.cfg, config_file = self._try_configs(files)
        err = None
        if self.cfg:
            try:
                ConfigValidation.check(self.cfg, self.program)
            except ConfigValidationError as e:
                err = str(e)
        else:
            err = 'No configuration files found!'

        if err:
            if argparser:
                argparser.error(err)
            else:
                logging.getLogger('slimta.app').error(err)
                sys.exit(2)

    def drop_privileges(self):
        process_options = self.cfg.process.get(self.program)
        user = process_options.get('user')
        group = process_options.get('group')
        if user or group:
            if os.getuid() == 0:
                slimta.system.drop_privileges(user, group)
            else:
                warnings.warn('Only superuser can drop privileges.')

    def redirect_streams(self):
        process_options = self.cfg.process.get(self.program)
        flag = process_options.get('daemon', False)
        if flag and not self.args.attached:
            so = process_options.get('stdout')
            se = process_options.get('stderr')
            si = process_options.get('stdin')
            slimta.system.redirect_stdio(so, se, si)

    def daemonize(self):
        flag = self.cfg.process.get(self.program).get('daemon', False)
        if self.args.attached is None and flag:
            slimta.system.daemonize()
        elif not self.args.attached:
            slimta.system.daemonize()

    def create_pid_file(self):
        args_pid_file = self.args.pid_file
        cfg_pid_file = self.cfg.process.get(self.program).get('pid_file')
        return slimta.system.PidFile(args_pid_file or cfg_pid_file)

    def setup_logging(self):
        settings = self.cfg.process.get(self.program).get('logging')
        setup_logging(settings)

    def _get_tls_options(self, tls_opts):
        if not tls_opts:
            return None
        tls_opts = dict(tls_opts).copy()
        certfile = tls_opts.pop('certfile', None)
        if certfile is not None:
            certfile = os.path.expandvars(certfile)
            certfile = os.path.expanduser(certfile)
            tls_opts['certfile'] = certfile
        keyfile = tls_opts.pop('keyfile', None)
        if keyfile is not None:
            keyfile = os.path.expandvars(keyfile)
            keyfile = os.path.expanduser(keyfile)
            tls_opts['keyfile'] = keyfile
        ca_certs = tls_opts.pop('ca_certs', None)
        if ca_certs is not None:
            ca_certs = os.path.expandvars(ca_certs)
            ca_certs = os.path.expanduser(ca_certs)
            tls_opts['ca_certs'] = ca_certs
        return tls_opts

    def _import_symbol(self, path):
        module_name, _, symbol_name = path.rpartition(':')
        if not module_name:
            module_name, _, symbol_name = path.rpartition('.')
        if not module_name:
            module_name, symbol_name = path, ''
        mod = import_module(module_name)
        if symbol_name:
            try:
                return getattr(mod, symbol_name)
            except AttributeError:
                raise ImportError('cannot import name '+symbol_name)
        else:
            return mod

    def _load_from_custom(self, options, *extra):
        factory = self._import_symbol(options.factory)
        return factory(options, *extra)

    def _get_listener(self, options, defaults):
        key = hash(tuple(options.iteritems()))
        if key in self.listeners:
            return self.listeners[key]
        type = options.get('type', 'tcp')
        new_listener = None
        if type in ('tcp', 'udp', 'unix'):
            if type == 'tcp':
                interface = options.get('interface', defaults.get('interface'))
                port = int(options.get('port', defaults.get('port')))
                new_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                address = (interface, port)
            elif type == 'udp':
                interface = options.get('interface', defaults.get('interface'))
                port = int(options.get('port', defaults.get('port')))
                new_listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                address = (interface, port)
            elif type == 'unix':
                new_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                address = options.get('path', defaults.get('path'))
            new_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            new_listener.setblocking(0)
            new_listener.bind(address)
            if type != 'udp':
                backlog = int(options.get('backlog', 256))
                new_listener.listen(backlog)
        elif type == 'custom':
            new_listener = self._load_from_custom(options)
        else:
            raise ValueError('Unknown listener type: {0}'.format(type))
        self.listeners[key] = new_listener
        return new_listener

    def _start_relay(self, name, options=None):
        if name in self.relays:
            return self.relays[name]
        if not options:
            options = getattr(self.cfg.relay, name)
        new_relay = None
        if options.type == 'mx':
            from slimta.relay.smtp.mx import MxSmtpRelay
            from .helpers import fill_hostname_template
            kwargs = {}
            kwargs['connect_timeout'] = options.get('connect_timeout', 30)
            kwargs['command_timeout'] = options.get('command_timeout', 30)
            kwargs['data_timeout'] = options.get('data_timeout', 60)
            kwargs['idle_timeout'] = options.get('idle_timeout', 10)
            kwargs['pool_size'] = options.get('concurrent_connections', 5)
            kwargs['ehlo_as'] = fill_hostname_template(options.get('ehlo_as'))
            if 'tls' in options:
                kwargs['tls'] = self._get_tls_options(options.tls)
            new_relay = MxSmtpRelay(**kwargs)
        elif options.type == 'static':
            from slimta.relay.smtp.static import StaticSmtpRelay
            from .helpers import fill_hostname_template, get_relay_credentials
            kwargs = {}
            kwargs['host'] = options.host
            kwargs['port'] = options.get('port', 25)
            kwargs['connect_timeout'] = options.get('connect_timeout', 30)
            kwargs['command_timeout'] = options.get('command_timeout', 30)
            kwargs['data_timeout'] = options.get('data_timeout', 60)
            kwargs['idle_timeout'] = options.get('idle_timeout', 10)
            kwargs['pool_size'] = options.get('concurrent_connections', 5)
            kwargs['ehlo_as'] = fill_hostname_template(options.get('ehlo_as'))
            if 'tls' in options:
                kwargs['tls'] = self._get_tls_options(options.tls)
            if 'credentials' in options:
                credentials = get_relay_credentials(options.get('credentials'))
                kwargs['credentials'] = credentials
            new_relay = StaticSmtpRelay(**kwargs)
        elif options.type == 'http':
            from slimta.relay.http import HttpRelay
            from .helpers import fill_hostname_template
            kwargs = {}
            kwargs['ehlo_as'] = fill_hostname_template(options.get('ehlo_as'))
            kwargs['timeout'] = options.get('timeout', 60)
            kwargs['idle_timeout'] = options.get('idle_timeout', 10)
            if 'tls' in options:
                kwargs['tls'] = self._get_tls_options(options.tls)
            new_relay = HttpRelay(options.url, **kwargs)
        elif options.type == 'blackhole':
            from slimta.relay.blackhole import BlackholeRelay
            new_relay = BlackholeRelay()
        elif options.type == 'maildrop':
            from slimta.piperelay import MaildropRelay
            path = options.get('path')
            new_relay = MaildropRelay(path)
        elif options.type == 'dovecot':
            from slimta.piperelay import DovecotRelay
            path = options.get('path')
            new_relay = DovecotRelay(path)
        elif options.type == 'custom':
            new_relay = self._load_from_custom(options)
        else:
            raise ConfigError('relay type does not exist: '+options.type)
        self.relays[name] = new_relay
        return new_relay

    def _start_queue(self, name, options=None):
        if name in self.queues:
            return self.queues[name]
        if not options:
            options = getattr(self.cfg.queue, name)
        from .helpers import add_queue_policies, build_backoff_function
        new_queue = None
        relay_name = options.get('relay')
        relay = self._start_relay(relay_name) if relay_name else None
        if options.type == 'memory':
            from slimta.queue import Queue
            from slimta.queue.dict import DictStorage
            store = DictStorage()
            backoff = build_backoff_function(options.get('retry'))
            new_queue = Queue(store, relay, backoff=backoff)
            new_queue.start()
        elif options.type == 'disk':
            from slimta.queue import Queue
            from slimta.diskstorage import DiskStorage
            env_dir = options.envelope_dir
            meta_dir = options.meta_dir
            tmp_dir = options.get('tmp_dir')
            store = DiskStorage(env_dir, meta_dir, tmp_dir)
            backoff = build_backoff_function(options.get('retry'))
            new_queue = Queue(store, relay, backoff=backoff)
            new_queue.start()
        elif options.type == 'redis':
            from slimta.queue import Queue
            from slimta.redisstorage import RedisStorage
            kwargs = {}
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
            if 'prefix' in options:
                kwargs['prefix'] = options.prefix
            store = RedisStorage(**kwargs)
            backoff = build_backoff_function(options.get('retry'))
            new_queue = Queue(store, relay, backoff=backoff)
            new_queue.start()
        elif options.type == 'proxy':
            from slimta.queue.proxy import ProxyQueue
            new_queue = ProxyQueue(relay)
        elif options.type == 'celery':
            from slimta.celeryqueue import CeleryQueue
            backoff = build_backoff_function(options.get('retry'))
            new_queue = CeleryQueue(self.celery, relay, name, backoff=backoff)
        elif options.type == 'custom':
            new_queue = self._load_from_custom(options, relay)
        else:
            raise ConfigError('queue type does not exist: '+options.type)
        add_queue_policies(new_queue, options.get('policies', []))
        self.queues[name] = new_queue
        return new_queue

    @property
    def celery(self):
        from .celery import get_celery_app
        if not self._celery:
            self._celery = get_celery_app(self.cfg)
        return self._celery

    def start_celery_queues(self):
        for name, options in dict(self.cfg.queue).items():
            if options.type == 'celery':
                self._start_queue(name, options)

    def _start_edge(self, name, options=None):
        if name in self.edges:
            return self.edges[name]
        if not options:
            options = getattr(self.cfg.edge, name)
        new_edge = None
        queue_name = options.queue
        queue = self._start_queue(queue_name)
        if options.type == 'smtp':
            from slimta.edge.smtp import SmtpEdge
            from .helpers import build_smtpedge_validators, build_smtpedge_auth
            from .helpers import fill_hostname_template
            listener_defaults = {'interface': '127.0.0.1', 'port': 25}
            listener = self._get_listener(options.listener, listener_defaults)
            kwargs = {}
            kwargs['tls'] = self._get_tls_options(options.get('tls'))
            kwargs['tls_immediately'] = options.get('tls_immediately', False)
            kwargs['validator_class'] = build_smtpedge_validators(options)
            kwargs['auth_class'] = build_smtpedge_auth(options)
            kwargs['command_timeout'] = 20.0
            kwargs['data_timeout'] = 30.0
            kwargs['max_size'] = int(options.get('max_size', 10485760))
            kwargs['hostname'] = fill_hostname_template(options.get('hostname'))
            new_edge = SmtpEdge(listener, queue, **kwargs)
            new_edge.start()
        elif options.type == 'http':
            from slimta.edge.wsgi import WsgiEdge
            from .helpers import build_wsgiedge_validators
            from .helpers import fill_hostname_template
            hostname = fill_hostname_template(options.get('hostname'))
            uri_pattern = options.get('uri')
            validator_class = build_wsgiedge_validators(options)
            new_edge = WsgiEdge(queue, hostname, validator_class, uri_pattern)
            listener_defaults = {'interface': '127.0.0.1', 'port': 8025}
            listener = self._get_listener(options.listener, listener_defaults)
            tls = self._get_tls_options(options.get('tls'))
            server = new_edge.build_server(listener, tls=tls)
            server.start()
        elif options.type == 'custom':
            new_edge = self._load_from_custom(options, queue)
        else:
            raise ConfigError('edge type does not exist: '+options.type)
        self.edges[name] = new_edge
        return new_edge

    def start_everything(self):
        if 'relay' in self.cfg:
            for name, options in dict(self.cfg.relay).items():
                self._start_relay(name, options)

        for name, options in dict(self.cfg.queue).items():
            self._start_queue(name, options)

        if 'edge' in self.cfg:
            for name, options in dict(self.cfg.edge).items():
                self._start_edge(name, options)

    def worker_loop(self):
        from .celery import get_celery_worker

        self.start_celery_queues()

        self.setup_logging()
        self.redirect_streams()
        self.daemonize()
        with slimta.system.PidFile(self.args.pid_file):
            sleep(0.1)
            self.drop_privileges()

            try:
                with self._with_sighandlers():
                    get_celery_worker(self.celery).run()
            except (KeyboardInterrupt, SystemExit):
                pass

    def loop(self):
        from gevent.event import Event

        self.start_everything()

        self.setup_logging()
        self.redirect_streams()
        self.daemonize()
        with self.create_pid_file():
            sleep(0.1)
            self.drop_privileges()

            try:
                with self._with_sighandlers():
                    Event().wait()
            except (KeyboardInterrupt, SystemExit):
                pass


# vim:et:fdm=marker:sts=4:sw=4:ts=4
