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

import os
import os.path
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
    argparser.add_argument('-a', '--no-daemon', dest='attached', action='store_true',
                    help='Override configs and force the process to remain attached to the terminal.')
    argparser.add_argument('-p', '--pid-file', metavar='FILE', default=None,
                    help='Store process ID in FILE during execution.')

    return argparser, argparser.parse_args()


def slimta():
    state = SlimtaState('slimta')
    state.load_config(*parse_args())

    state.start_edges()

    state.setup_logging()
    state.redirect_streams()
    state.daemonize()
    sleep(0.1)
    state.drop_privileges()

    state.loop()


def worker():
    state = SlimtaState('worker')
    state.load_config(*parse_args())

    state.start_celery_queues()

    state.setup_logging()
    state.redirect_streams()
    state.daemonize()
    sleep(0.1)
    state.drop_privileges()

    state.worker_loop()


def _try_config_copy(etc_dir, conf_file, force):
    final_path = os.path.join(etc_dir, conf_file)
    if not force and os.path.exists(final_path):
        while True:
            confirm = raw_input(final_path+' already exists, overwrite? [y/N] ')
            if confirm.lower() == 'y':
                break
            elif not confirm or confirm.lower() == 'n':
                return
    from pkg_resources import resource_string
    resource_name = 'etc/{0}.sample'.format(conf_file)
    contents = resource_string('slimta.app', resource_name)
    contents = contents.replace('slimta.conf.sample', 'slimta.conf')
    contents = contents.replace('rules.conf.sample', 'rules.conf')
    contents = contents.replace('logging.conf.sample', 'logging.conf')
    with open(final_path, 'w') as f:
        f.write(contents)


def setup():
    argparser = ArgumentParser(description='Create starting configs for a slimta instance.')
    argparser.add_argument('--version', action='version', version='%(prog)s '+VERSION)
    argparser.add_argument('-e', '--etc-dir', metavar='DIR', default=None,
                           help='Place new configs in DIR. By default, this script will prompt the user for a directory.')
    argparser.add_argument('-f', '--force', action='store_true', default=False,
                           help='Force overwriting if destination files exist. The user is prompted by default.')
    args = argparser.parse_args()

    etc_dir = args.etc_dir
    default_etc_dir = '/etc/slimta'
    if os.getuid() != 0:
        default_etc_dir = '~/.slimta/'
    if etc_dir is None:
        etc_dir = raw_input('Where should slimta config files be placed? [{0}] '.format(default_etc_dir))
        if not etc_dir:
            etc_dir = default_etc_dir
    etc_dir = os.path.expandvars(os.path.expanduser(etc_dir))
    try:
        os.makedirs(etc_dir, 0755)
    except OSError as (err, msg):
        if err != 17:
            raise

    _try_config_copy(etc_dir, 'slimta.conf', args.force)
    _try_config_copy(etc_dir, 'rules.conf', args.force)
    _try_config_copy(etc_dir, 'logging.conf', args.force)


# vim:et:fdm=marker:sts=4:sw=4:ts=4
