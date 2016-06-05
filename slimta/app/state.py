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

from gevent import sleep, socket
from gevent.event import AsyncResult
import slimta.system

from .validation import ConfigValidation, ConfigValidationError
from .config import try_configs
from .logging import setup_logging

try:
    from slimta.util import build_ipv4_socket_creator
except ImportError as exc:
    def build_ipv4_socket_creator(*args, **kwargs):
        raise exc


class SlimtaState(object):

    _global_config_files = [os.path.expanduser('~/.slimta/slimta.yaml'),
                            '/etc/slimta/slimta.yaml']

    def __init__(self, args):
        self.program = os.path.basename(sys.argv[0])
        self.args = args
        self.cfg = None
        self.loop_interrupt = AsyncResult()
        self.cached_listeners = {}
        self.listeners = {}
        self.edges = {}
        self.queues = {}
        self.relays = {}

    @contextmanager
    def _with_sighandlers(self):
        from signal import SIGTERM, SIGHUP
        from gevent import signal
        def handle_term():
            sys.exit(0)
        def handle_hup():
            self.loop_interrupt.set('reload')
        old_term = signal(SIGTERM, handle_term)
        old_hup = signal(SIGHUP, handle_hup)
        try:
            yield
        finally:
            signal(SIGTERM, old_term)
            signal(SIGHUP, old_hup)

    def load_config(self, argparser=None):
        if self.args.process_name:
            self.program = self.args.process_name

        files = self._global_config_files
        if self.args.config:
            files = [self.args.config]

        self.cfg = try_configs(files)
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

    def _copy_listener(self, listener):
        if isinstance(listener, socket.socket):
            fd = listener.fileno()
            family = listener.family
            type = listener.type
            proto = listener.proto
            return socket.fromfd(fd, family, type, proto)
        return listener

    def _get_listener(self, options, defaults):
        key = hash(tuple(options.iteritems()))
        if key in self.cached_listeners:
            existing = self.cached_listeners[key]
            listener_copy = self._copy_listener(existing)
            self.listeners[key] = listener_copy
            return listener_copy
        type = options.get('type', 'tcp')
        new_listener = None
        if type in ('tcp', 'udp', 'unix'):
            if type == 'tcp':
                interface = options.get('interface', defaults.get('interface'))
                port = int(options.get('port', defaults.get('port')))
                new_listener = socket.socket(socket.AF_INET,
                                             socket.SOCK_STREAM)
                address = (interface, port)
            elif type == 'udp':
                interface = options.get('interface', defaults.get('interface'))
                port = int(options.get('port', defaults.get('port')))
                new_listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                address = (interface, port)
            elif type == 'unix':
                new_listener = socket.socket(socket.AF_UNIX,
                                             socket.SOCK_STREAM)
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
            if options.get('ipv4_only'):
                kwargs['socket_creator'] = build_ipv4_socket_creator([25])
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
            if options.get('ipv4_only'):
                kwargs['socket_creator'] = \
                    build_ipv4_socket_creator([kwargs['port']])
            new_relay = StaticSmtpRelay(**kwargs)
        elif options.type == 'lmtp':
            from slimta.relay.smtp.static import StaticLmtpRelay
            from .helpers import fill_hostname_template, get_relay_credentials
            kwargs = {}
            kwargs['host'] = options.get('host', 'localhost')
            kwargs['port'] = options.get('port', 24)
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
            if options.get('ipv4_only'):
                kwargs['socket_creator'] = \
                    build_ipv4_socket_creator([kwargs['port']])
            new_relay = StaticLmtpRelay(**kwargs)
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
            from slimta.relay.pipe import MaildropRelay
            path = options.get('path')
            new_relay = MaildropRelay(path)
        elif options.type == 'dovecot':
            from slimta.relay.pipe import DovecotLdaRelay
            path = options.get('path')
            new_relay = DovecotLdaRelay(path)
        elif options.type == 'custom':
            new_relay = self._load_from_custom(options)
        else:
            msg = 'relay type does not exist: '+options.type
            raise ConfigValidationError(msg)
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
        bounce_queue_name = options.get('bounce_queue', name)
        bounce_queue = self._start_queue(bounce_queue_name) \
                       if bounce_queue_name != name else None
        if options.type == 'memory':
            from slimta.queue import Queue
            from slimta.queue.dict import DictStorage
            store = DictStorage()
            backoff = build_backoff_function(options.get('retry'))
            new_queue = Queue(store, relay, backoff=backoff,
                              bounce_queue=bounce_queue)
            new_queue.start()
        elif options.type == 'disk':
            from slimta.queue import Queue
            from slimta.diskstorage import DiskStorage
            env_dir = options.envelope_dir
            meta_dir = options.meta_dir
            tmp_dir = options.get('tmp_dir')
            store = DiskStorage(env_dir, meta_dir, tmp_dir)
            backoff = build_backoff_function(options.get('retry'))
            new_queue = Queue(store, relay, backoff=backoff,
                              bounce_queue=bounce_queue)
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
            new_queue = Queue(store, relay, backoff=backoff,
                              bounce_queue=bounce_queue)
            new_queue.start()
        elif options.type == 'rackspace':
            from slimta.queue import Queue
            from slimta.cloudstorage import CloudStorage
            from slimta.cloudstorage.rackspace import RackspaceCloudAuth, \
                    RackspaceCloudFiles, RackspaceCloudQueues
            tls = self._get_tls_options(options.get('tls'))
            credentials = {'username': options.username}
            if 'password' in options:
                credentials['password'] = options.password
            if 'api_key' in options:
                credentials['api_key'] = options.api_key
            if 'tenant_id' in options:
                credentials['tenant_id'] = options.tenant_id
            auth_kwargs = {'region': options.get('region'),
                           'timeout': 10.0,
                           'tls': tls}
            if 'endpoint' in options:
                auth_kwargs['endpoint'] = options.endpoint
            auth = RackspaceCloudAuth(credentials, **auth_kwargs)
            cloud_files = RackspaceCloudFiles(auth,
                    container=options.container_name,
                    tls=tls, timeout=20.0)
            cloud_queues = None
            if 'queue_name' in options:
                cloud_queues = RackspaceCloudQueues(auth,
                        queue_name=options.queue_name,
                        tls=tls, timeout=10.0)
            store = CloudStorage(cloud_files, cloud_queues)
            new_queue = Queue(store, relay, backoff=backoff,
                              bounce_queue=bounce_queue)
            new_queue.start()
        elif options.type == 'aws':
            from slimta.queue import Queue
            from slimta.cloudstorage import CloudStorage
            from slimta.cloudstorage.aws import SimpleStorageService, \
                    SimpleQueueService
            import boto
            if 'access_key_id' in options:
                from boto.s3.connection import S3Connection
                s3_conn = S3Connection(options.access_key_id,
                                       options.secret_access_key)
            else:
                s3_conn = boto.connect_s3()
            s3_bucket = s3_conn.get_bucket(options.bucket_name)
            s3 = SimpleStorageService(s3_bucket, timeout=20.0)
            sqs = None
            if 'queue_name' in options:
                from boto.sqs import connect_to_region
                region = options.get('queue_region', 'us-west-2')
                if 'access_key_id' in options:
                    sqs_conn = connect_to_region(region,
                            aws_access_key_id=options.access_key_id,
                            aws_secret_access_key=options.secret_access_key)
                else:
                    sqs_conn = connect_to_region(region)
                sqs_queue = sqs_conn.create_queue(options.queue_name)
                sqs = SimpleQueueService(sqs_queue, timeout=10.0)
            store = CloudStorage(s3, sqs)
            new_queue = Queue(store, relay, backoff=backoff,
                              bounce_queue=bounce_queue)
            new_queue.start()
        elif options.type == 'proxy':
            from slimta.queue.proxy import ProxyQueue
            new_queue = ProxyQueue(relay)
        elif options.type == 'custom':
            new_queue = self._load_from_custom(options, relay)
        else:
            msg = 'queue type does not exist: '+options.type
            raise ConfigValidationError()
        add_queue_policies(new_queue, options.get('policies', []))
        self.queues[name] = new_queue
        return new_queue

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
            from .helpers import build_smtpedge_validators
            from .helpers import fill_hostname_template
            hostname = fill_hostname_template(options.get('hostname'))
            listener_defaults = {'interface': '127.0.0.1', 'port': 25}
            listener = self._get_listener(options.listener, listener_defaults)
            kwargs = {}
            kwargs['tls'] = self._get_tls_options(options.get('tls'))
            kwargs['tls_immediately'] = options.get('tls_immediately', False)
            kwargs['validator_class'] = build_smtpedge_validators(options)
            kwargs['auth'] = ['PLAIN', 'LOGIN']
            kwargs['command_timeout'] = 20.0
            kwargs['data_timeout'] = 30.0
            kwargs['max_size'] = int(options.get('max_size', 10485760))
            kwargs['hostname'] = hostname
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
            msg = 'edge type does not exist: '+options.type
            raise ConfigValidationError(msg)
        self.edges[name] = new_edge
        return new_edge

    def reload_config(self):
        self.load_config()
        old_edges = self.edges.copy()
        old_queues = self.queues.copy()
        old_relays = self.relays.copy()
        self.edges = {}
        self.queues = {}
        self.relays = {}
        self.start_everything()
        for edge in old_edges.itervalues():
            edge.kill()
        for queue in old_queues.itervalues():
            queue.kill()
        for relay in old_relays.itervalues():
            relay.kill()

    def _handle_loop_interrupts(self, action):
        if action == 'reload':
            self.reload_config()

    def start_everything(self):
        self.cached_listeners = self.listeners.copy()
        self.listeners = {}

        if 'relay' in self.cfg:
            for name, options in dict(self.cfg.relay).items():
                self._start_relay(name, options)

        for name, options in dict(self.cfg.queue).items():
            self._start_queue(name, options)

        if 'edge' in self.cfg:
            for name, options in dict(self.cfg.edge).items():
                self._start_edge(name, options)

        self.cached_listeners = {}

    def loop(self):
        self.start_everything()

        self.setup_logging()
        self.redirect_streams()
        self.daemonize()
        with self.create_pid_file():
            sleep(0.1)
            self.drop_privileges()

            try:
                with self._with_sighandlers():
                    while True:
                        action = self.loop_interrupt.get()
                        self.loop_interrupt = AsyncResult()
                        self._handle_loop_interrupts(action)
            except (KeyboardInterrupt, SystemExit):
                pass


# vim:et:fdm=marker:sts=4:sw=4:ts=4
