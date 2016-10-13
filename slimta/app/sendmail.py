# Copyright (c) 2016 Ian C. Good
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

import os
import sys
from argparse import ArgumentParser

os.environ['GEVENT_RESOLVER'] = 'ares'
from gevent import monkey; monkey.patch_all()

from slimta.envelope import Envelope
from . import __version__
from .state import SlimtaState


def parse_args():
    argparser = ArgumentParser(description='Sendmail compatible script for delivering email on the command-line.')
    argparser.add_argument('--version', action='version', version='%(prog)s '+__version__)
    argparser.add_argument('-c', '--config', metavar='FILE', default=None,
                    help='Specifies a configuration file to read. If not given, the default locations ($HOME/.slimta/slimta.yaml, /etc/slimta/slimta.yaml) are checked.')
    argparser.add_argument('-f', '--from', metavar='ADDRESS', default=None, dest='sender',
                    help='The envelope sender address for the mail')
    argparser.add_argument('recipients', metavar='ADDRESS', nargs='+',
                    help='The envelope recipient addresses for the mail')
    argparser.set_defaults(process_name=None,
                           attached=True)

    return argparser, argparser.parse_known_args()[0]


def load_envelope(args, file):
    env = Envelope(args.sender, args.recipients)
    env.parse(file.read())
    return env


def main():
    argparser, args = parse_args()
    state = SlimtaState(args)
    state.load_config(argparser=argparser)

    env = load_envelope(args, sys.stdin)
    state.sendmail(env)


# vim:et:fdm=marker:sts=4:sw=4:ts=4
