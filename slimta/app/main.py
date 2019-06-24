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
from argparse import ArgumentParser

os.environ['GEVENT_RESOLVER'] = 'ares'
from gevent import monkey; monkey.patch_all()

from . import __version__
from .state import SlimtaState


def parse_args():
    argparser = ArgumentParser(description='Configurable MTA based on the python-slimta libraries.')
    argparser.add_argument('--version', action='version', version='%(prog)s '+__version__)
    argparser.add_argument('-c', '--config', metavar='FILE', default=None,
                    help='Specifies a configuration file to read. If not given, the default locations ($HOME/.slimta/slimta.yaml, /etc/slimta/slimta.yaml) are checked.')
    argparser.add_argument('-n', '--process-name', metavar='NAME', default=None,
                    help='Use the process sub-section NAME for configuration. By default, the name of the executable is used.')
    argparser.add_argument('-a', '--no-daemon', dest='attached', action='store_true',
                    help='Override configs and force the process to remain attached to the terminal.')
    argparser.add_argument('-d', '--daemon', dest='attached', action='store_false',
                    help='Override configs and force the process to daemonize.')
    argparser.add_argument('-p', '--pid-file', metavar='FILE', default=None,
                    help='Store process ID in FILE during execution.')
    argparser.set_defaults(attached=None)

    return argparser, argparser.parse_args()


def main():
    argparser, args = parse_args()
    state = SlimtaState(args)
    state.load_config(argparser=argparser)

    state.loop()


# vim:et:fdm=marker:sts=4:sw=4:ts=4
