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
from argparse import ArgumentParser

from config import Config
import slimta.system

from .core import VERSION
from .config import load_config


class SlimtaApp(object):

    def __init__(self):
        self.ap = ArgumentParser(description='Configurable MTA based on the python-slimta libraries.')
        self.args = None
        self.cfg = None

    def parse_args(self):
        self.ap.add_argument('--version', action='version', version='%(prog)s '+VERSION)
        self.ap.add_argument('-c', '--config', metavar='FILE', default=None,
                        help='Specifies a configuration file to read. If not given, the default locations ($HOME/.slimta.conf, f/etc/slimta.conf) are checked.')
        self.ap.add_argument('-a', '--attached', action='store_true',
                        help='Prevent process from daemonizing, overriding configs.')
        self.args = self.ap.parse_args()

        self.cfg = load_config(self.args.config)

    def drop_privileges(self):
        if os.getuid() == 0:
            user = self.cfg.process.get('user')
            group = self.cfg.process.get('group')
            slimta.system.drop_privileges(user, group)
        else:
            warnings.warn('Only superuser can drop privileges.')

    def redirect_streams(self):
        if not self.args.attached:
            so = self.cfg.process.get('stdout')
            se = self.cfg.process.get('stderr')
            si = self.cfg.process.get('stdin')
            slimta.system.redirect_stdio(so, se, si)

    def daemonize(self):
        flag = self.cfg.process.get('daemon', False)
        if flag and not self.args.attached:
            slimta.system.daemonize()

    def _start_relay(self, stack, options):
        from slimta.relay.maildrop import MaildropRelay
        from slimta.relay.smtp.mx import MxSmtpRelay
        from slimta.relay.smtp.static import StaticSmtpRelay

        if options.type == 'mx':
            return MxSmtpRelay()
        elif options.type == 'static':
            host = options.host
            port = options.get('port', 25)
            return StaticSmtpRelay(host, port)
        elif options.type == 'maildrop':
            executable = options.get('executable')
            return MaildropRelay(executable=executable)

    def _start_queue(self, stack, options, relay):
        if not options or options.get('type', 'default') == 'default':
            from slimta.queue import Queue
            pass
        elif options.type == 'celery':
            from slimta.celeryqueue import CeleryQueue
            from .celery import celery
            celery_config = self.cfg.celery_app
            celery.config_from_object(celery_config)
            return CeleryQueue(celery, relay, stack)

    def start_services(self):
        for stack, options in dict(self.cfg.stack).items():
            pass

    def loop(self):
        from gevent.event import Event
        try:
            Event().wait()
        except (KeyboardInterrupt, SystemExit):
            print


class CeleryApp(object):

    def __init__(self, cfg):
        self.cfg = cfg
        self.celery = self._build_app()

    def _build_app(self):
        from celery import Celery
        celery = Celery('slimta.app.tasks',
                        broker=self.cfg.celery_app.get('broker'),
                        backend=self.cfg.celery_app.get('backend'))
        return celery

    def new_queue(self, identifier, relay, backoff=None, bounce_factory=None):
        from slimta.celeryqueue import CeleryQueue
        ret = CeleryQueue(self.celery, relay, identifier, backoff,
                          bounce_factory)
        return ret

    def run_worker(self):
        worker_args = ['-A', 'slimta.app.tasks']
        worker_args += self.cfg.celery_app.get('worker_args', [])
        self.celery.worker_main(worker_args)


def main():
    app = SlimtaApp()
    app.parse_args()

    app.start_services()

    app.drop_privileges()
    app.redirect_streams()
    app.daemonize()

    app.loop()


# vim:et:fdm=marker:sts=4:sw=4:ts=4
