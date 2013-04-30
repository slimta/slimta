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

from argparse import ArgumentParser

from gevent import monkey; monkey.patch_all()
from gevent import sleep

from .core import VERSION
from .state import SlimtaState


def parse_args():
    argparser = ArgumentParser(description='Configurable MTA based on the python-slimta libraries.')
    argparser.add_argument('--version', action='version', version='%(prog)s '+VERSION)
    argparser.add_argument('-c', '--config', metavar='FILE', default=None,
                    help='Specifies a configuration file to read. If not given, the default locations ($HOME/.slimta/slimta.conf, /etc/slimta/slimta.conf) are checked.')
    argparser.add_argument('-a', '--no-daemon', dest='daemon', action='store_false', default=None,
                    help='Override configs and force the process to remain attached to the terminal.')
    argparser.add_argument('-p', '--pid-file', metavar='FILE', default=None,
                    help='Store process ID in FILE during execution.')

    return argparser, argparser.parse_args()


def main():
    state = SlimtaState('worker')
    state.load_config(*parse_args())

    state.start_celery_queues()

    state.setup_logging()
    state.redirect_streams()
    state.daemonize()
    sleep(0.1)
    state.drop_privileges()

    state.worker_loop()


# vim:et:fdm=marker:sts=4:sw=4:ts=4
