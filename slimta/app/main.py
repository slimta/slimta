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

import os
import os.path
import sys
from argparse import ArgumentParser

os.environ['GEVENT_RESOLVER'] = 'ares'
from gevent import monkey  # noqa
monkey.patch_all()

from . import __version__  # noqa
from .state import SlimtaState  # noqa


def parse_args():
    argparser = ArgumentParser(description='Configurable MTA based on the '
                               'python-slimta libraries.')
    argparser.add_argument('--version', action='version',
                           version='%(prog)s '+__version__)
    argparser.add_argument('-a', '--no-daemon', dest='attached',
                           action='store_true',
                           help='Force the process to remain attached to the '
                           'terminal.')
    argparser.add_argument('-d', '--daemon', dest='attached',
                           action='store_false',
                           help='Force the process to daemonize.')
    argparser.add_argument('-p', '--pid-file', metavar='FILE', default=None,
                           help='Store process ID in FILE during execution.')

    default_process_name = os.path.basename(sys.argv[0])
    group = argparser.add_argument_group('config options')
    group.add_argument('-c', '--config', metavar='FILE', default=None,
                       help='Specifies a configuration file to read. If not '
                       'given, the default locations '
                       '($HOME/.slimta/slimta.yaml, /etc/slimta/slimta.yaml) '
                       'are checked.')
    group.add_argument('-n', '--process-name', metavar='NAME',
                       default=default_process_name,
                       help='Use the process sub-section NAME for '
                       'configuration. (default: %(default)s)')
    group.add_argument('--no-edge', action='store_true',
                       help='Ignore all configured edges.')
    group.add_argument('--no-relay', action='store_true',
                       help='Ignore all configured relays.')

    argparser.set_defaults(attached=None)
    return argparser, argparser.parse_args()


def main():
    argparser, args = parse_args()
    state = SlimtaState(args)
    state.load_config(argparser=argparser)

    state.loop()


# vim:et:fdm=marker:sts=4:sw=4:ts=4
