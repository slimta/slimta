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

import sys
import os
import os.path
import socket
import warnings
import logging
from contextlib import contextmanager

from gevent import sleep, ssl
from gevent.event import AsyncResult
from slimta.util import system
from slimta.util.proxyproto import ProxyProtocol

from .validation import ConfigValidation, ConfigValidationError
from .config import try_configs
from .importutil import custom_factory
from .listeners import Listeners
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
        self.program = args.process_name
        self.args = args
        self.cfg = None
        self.loop_interrupt = AsyncResult()
        self.ssl_contexts = {}
        self.cached_listeners = {}
        self.listeners = {}
        self.queues = {}
        self.relays = {}
        self.edges = []

    @contextmanager
    def _with_sighandlers(self):
        from signal import SIGTERM, SIGHUP, SIG_DFL
        from gevent import signal
        def handle_term(signum, frame):
            sys.exit(0)
        def handle_hup(signum, frame):
            self.loop_interrupt.set('reload')
        old_term = signal.signal(SIGTERM, handle_term) or SIG_DFL
        old_hup = signal.signal(SIGHUP, handle_hup) or SIG_DFL
        try:
            yield
        finally:
            signal.signal(SIGTERM, old_term)
            signal.signal(SIGHUP, old_hup)

    def load_config(self, argparser=None):
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

    def override_hostname(self):
        process_options = self.cfg.process[self.program]
        hostname = process_options.hostname
        fqdn = process_options.fqdn
        if hostname is not None:
            socket.gethostname = lambda: hostname
        if fqdn is not None:
            socket.getfqdn = lambda: fqdn

    def drop_privileges(self):
        process_options = self.cfg.process[self.program]
        user = process_options.user
        group = process_options.group
        if user or group:
            if os.getuid() == 0:
                system.drop_privileges(user, group)
            else:
                warnings.warn('Only superuser can drop privileges.')

    @property
    def is_daemon(self):
        daemon = self.cfg.process[self.program].daemon
        attached = self.args.attached
        return attached is False or (attached is None and daemon)

    def redirect_streams(self):
        if self.is_daemon:
            process_options = self.cfg.process[self.program]
            so = process_options.stdout
            se = process_options.stderr
            si = process_options.stdin
            system.redirect_stdio(so, se, si)

    def daemonize(self):
        if self.is_daemon:
            system.daemonize()

    def create_pid_file(self):
        args_pid_file = self.args.pid_file
        cfg_pid_file = self.cfg.process[self.program].pid_file
        return system.PidFile(args_pid_file or cfg_pid_file)

    def setup_logging(self):
        settings = self.cfg.process[self.program].logging
        setup_logging(settings)

    def _get_client_ssl_context(self, tls_opts):
        purpose = ssl.Purpose.SERVER_AUTH
        if not tls_opts:
            return ssl.create_default_context(purpose)
        else:
            return self._get_ssl_context(purpose, tls_opts)

    def _get_server_ssl_context(self, tls_opts):
        purpose = ssl.Purpose.CLIENT_AUTH
        if not tls_opts:
            return None
        else:
            return self._get_ssl_context(purpose, tls_opts)

    def _get_ssl_context(self, purpose, tls_opts):
        key = (purpose, hash(tuple(tls_opts.items())))
        if key in self.ssl_contexts:
            return self.ssl_contexts[key]
        ctx = ssl.create_default_context(purpose)
        certfile = tls_opts.certfile
        keyfile = tls_opts.keyfile
        cafile = tls_opts.ca_certs
        if certfile is not None:
            certfile = os.path.expandvars(certfile)
            certfile = os.path.expanduser(certfile)
        if keyfile is not None:
            keyfile = os.path.expandvars(keyfile)
            keyfile = os.path.expanduser(keyfile)
        if cafile is not None:
            cafile = os.path.expandvars(cafile)
            cafile = os.path.expanduser(cafile)
        if certfile or keyfile:
            ctx.load_cert_chain(certfile, keyfile)
        if cafile:
            ctx.load_verify_locations(cafile)
        self.ssl_contexts[key] = ctx
        return ctx

    def _start_relay(self, name, options=None):
        if self.args.no_relay:
            return None
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
            kwargs['ehlo_as'] = fill_hostname_template(options.ehlo_as)
            kwargs['context'] = self._get_client_ssl_context(options.tls)
            if options.ipv4_only:
                kwargs['socket_creator'] = build_ipv4_socket_creator([25])
            new_relay = MxSmtpRelay(**kwargs)
            if 'force_mx' in options:
                for domain, dest in options.force_mx:
                    new_relay.force_mx(domain, dest)
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
            kwargs['ehlo_as'] = fill_hostname_template(options.ehlo_as)
            kwargs['context'] = self._get_client_ssl_context(options.tls)
            if 'credentials' in options:
                credentials = get_relay_credentials(options.credentials)
                kwargs['credentials'] = credentials
            if options.ipv4_only:
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
            kwargs['ehlo_as'] = fill_hostname_template(options.ehlo_as)
            kwargs['context'] = self._get_client_ssl_context(options.tls)
            if 'credentials' in options:
                credentials = get_relay_credentials(options.credentials)
                kwargs['credentials'] = credentials
            if options.ipv4_only:
                kwargs['socket_creator'] = \
                    build_ipv4_socket_creator([kwargs['port']])
            new_relay = StaticLmtpRelay(**kwargs)
        elif options.type == 'http':
            from slimta.relay.http import HttpRelay
            from .helpers import fill_hostname_template
            kwargs = {}
            kwargs['ehlo_as'] = fill_hostname_template(options.ehlo_as)
            kwargs['timeout'] = options.get('timeout', 60)
            kwargs['idle_timeout'] = options.get('idle_timeout', 10)
            kwargs['context'] = self._get_client_ssl_context(options.tls)
            new_relay = HttpRelay(options.url, **kwargs)
        elif options.type == 'blackhole':
            from slimta.relay.blackhole import BlackholeRelay
            new_relay = BlackholeRelay()
        elif options.type == 'pipe':
            from slimta.relay.pipe import PipeRelay
            new_relay = PipeRelay(options.args)
        elif options.type == 'maildrop':
            from slimta.relay.pipe import MaildropRelay
            path = options.path
            new_relay = MaildropRelay(path)
        elif options.type == 'dovecot':
            from slimta.relay.pipe import DovecotLdaRelay
            path = options.path
            new_relay = DovecotLdaRelay(path)
        elif options.type == 'custom':
            new_relay = custom_factory(options)
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
        relay_name = options.relay
        relay = self._start_relay(relay_name) if relay_name else None
        bounce_queue_name = options.get('bounce_queue', name)
        bounce_queue = self._start_queue(bounce_queue_name) \
                       if bounce_queue_name != name else None
        if options.type == 'memory':
            from slimta.queue import Queue
            from slimta.queue.dict import DictStorage
            store = DictStorage()
            backoff = build_backoff_function(options.retry)
            new_queue = Queue(store, relay, backoff=backoff,
                              bounce_queue=bounce_queue)
            new_queue.start()
        elif options.type == 'disk':
            from slimta.queue import Queue
            from slimta.diskstorage import DiskStorage
            env_dir = options.envelope_dir
            meta_dir = options.meta_dir
            tmp_dir = options.tmp_dir
            store = DiskStorage(env_dir, meta_dir, tmp_dir)
            backoff = build_backoff_function(options.retry)
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
            backoff = build_backoff_function(options.retry)
            new_queue = Queue(store, relay, backoff=backoff,
                              bounce_queue=bounce_queue)
            new_queue.start()
        elif options.type == 'rackspace':
            from slimta.queue import Queue
            from slimta.cloudstorage import CloudStorage
            from slimta.cloudstorage.rackspace import RackspaceCloudAuth, \
                    RackspaceCloudFiles, RackspaceCloudQueues
            credentials = {'username': options.username}
            if 'password' in options:
                credentials['password'] = options.password
            if 'api_key' in options:
                credentials['api_key'] = options.api_key
            if 'tenant_id' in options:
                credentials['tenant_id'] = options.tenant_id
            auth_kwargs = {'region': options.region,
                           'timeout': 10.0}
            if 'endpoint' in options:
                auth_kwargs['endpoint'] = options.endpoint
            auth = RackspaceCloudAuth(credentials, **auth_kwargs)
            cloud_files = RackspaceCloudFiles(auth,
                    container=options.container_name, timeout=20.0)
            cloud_queues = None
            if 'queue_name' in options:
                cloud_queues = RackspaceCloudQueues(auth,
                        queue_name=options.queue_name, timeout=10.0)
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
            new_queue = custom_factory(options, relay)
        else:
            msg = 'queue type does not exist: '+options.type
            raise ConfigValidationError(msg)
        add_queue_policies(new_queue, options.get('policies', []))
        self.queues[name] = new_queue
        return new_queue

    def _start_edge(self, name, options=None):
        if self.args.no_edge:
            return None
        if not options:
            options = getattr(self.cfg.edge, name)
        queue_name = options.queue
        queue = self._start_queue(queue_name)
        if options.type == 'smtp':
            from slimta.edge.smtp import SmtpEdge
            from .helpers import build_smtpedge_validators
            from .helpers import fill_hostname_template
            kwargs = {}
            kwargs['context'] = self._get_server_ssl_context(options.tls)
            kwargs['tls_immediately'] = options.tls_immediately
            kwargs['validator_class'] = build_smtpedge_validators(options)
            kwargs['auth'] = [b'PLAIN', b'LOGIN']
            kwargs['command_timeout'] = 20.0
            kwargs['data_timeout'] = 30.0
            kwargs['max_size'] = int(options.get('max_size', 10485760))
            kwargs['hostname'] = fill_hostname_template(options.hostname)
            for listener in Listeners(options, 25):
                new_edge = SmtpEdge(listener, queue, **kwargs)
                if options.proxyprotocol:
                    ProxyProtocol.mixin(new_edge)
                new_edge.start()
                self.edges.append(new_edge)
        elif options.type == 'http':
            from slimta.edge.wsgi import WsgiEdge
            from .helpers import build_wsgiedge_validators
            from .helpers import fill_hostname_template
            kwargs = {}
            kwargs['hostname'] = fill_hostname_template(options.hostname)
            kwargs['validator_class'] = build_wsgiedge_validators(options)
            kwargs['uri_pattern'] = options.uri
            kwargs['context'] = self._get_server_ssl_context(options.tls)
            listener = self._get_listener(options, 8025)
            for listener in Listeners(options, 8025):
                new_edge = WsgiEdge(queue, listener=listener, **kwargs)
                if options.proxyprotocol:
                    ProxyProtocol.mixin(new_edge)
                new_edge.start()
                self.edges.append(new_edge)
        elif options.type == 'custom':
            new_edge = custom_factory(options, queue)
            self.edges.append(new_edge)
        else:
            msg = 'edge type does not exist: '+options.type
            raise ConfigValidationError(msg)

    def reload_config(self):
        self.load_config()
        old_edges = self.edges[:]
        old_queues = self.queues.copy()
        old_relays = self.relays.copy()
        self.edges = []
        self.queues = {}
        self.relays = {}
        self.start_everything()
        for edge in old_edges:
            edge.kill()
        for queue in old_queues.values():
            queue.kill()
        for relay in old_relays.values():
            relay.kill()

    def _handle_loop_interrupts(self, action):
        if action == 'reload':
            self.reload_config()

    def start_everything(self):
        self.cached_listeners = self.listeners.copy()
        self.listeners = {}

        if 'relay' in self.cfg:
            for name, options in list(dict(self.cfg.relay).items()):
                self._start_relay(name, options)

        for name, options in list(dict(self.cfg.queue).items()):
            self._start_queue(name, options)

        if 'edge' in self.cfg:
            for name, options in list(dict(self.cfg.edge).items()):
                self._start_edge(name, options)

        self.cached_listeners = {}

    def loop(self):
        self.override_hostname()
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
