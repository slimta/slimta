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
import sys
import subprocess
from string import Template
from argparse import ArgumentParser

from . import __version__


def _confirm_overwrite(path, force=False):
    if not force and os.path.exists(path):
        while True:
            confirm = raw_input(path+' already exists, overwrite? [y/N] ')
            if confirm.lower() == 'y':
                return True
            elif not confirm or confirm.lower() == 'n':
                return False
    return True


def _try_config_copy(etc_dir, conf_file, force):
    final_path = os.path.join(etc_dir, conf_file)
    if not _confirm_overwrite(final_path, force):
        return
    from pkg_resources import resource_string
    resource_name = 'etc/{0}.sample'.format(conf_file)
    contents = resource_string('slimta.app', resource_name)
    contents = contents.replace('slimta.conf.sample', 'slimta.conf')
    contents = contents.replace('rules.conf.sample', 'rules.conf')
    contents = contents.replace('logging.conf.sample', 'logging.conf')
    with open(final_path, 'w') as f:
        f.write(contents)


def _setup_configs(args):
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


def _setup_inits(args):
    from pkg_resources import resource_string
    resource_name = 'etc/init-{0}.tmpl'.format(args.type)
    template_str = resource_string('slimta.app', resource_name)
    tmpl = Template(template_str)
    pid_file = os.path.join(args.pid_dir, '{0}.pid'.format(args.name))
    contents = tmpl.safe_substitute(service_name=args.name,
                                    service_config=args.config_file,
                                    service_daemon=args.daemon,
                                    service_pidfile=pid_file)
    if args.type == 'systemd':
        init_dir = args.init_dir or '/etc/systemd/system'
        init_file = os.path.join(init_dir, '{0}.service'.format(args.name))
    elif args.type == 'lsb':
        init_dir = args.init_dir or '/etc/init.d'
        init_file = os.path.join(init_dir, args.name)
    if not _confirm_overwrite(init_file):
        return
    with open(init_file, 'w') as f:
        f.write(contents)
        if args.type in ('lsb', ):
            os.fchmod(f.fileno(), 0755)

    if args.enable:
        cmd = None
        if args.type == 'systemd':
            cmd = 'systemctl enable {0}'.format(args.name)
        elif args.type == 'lsb':
            cmd = 'update-rc.d {0} defaults'.format(args.name)
        if cmd:
            p = subprocess.Popen(cmd, shell=True)
            p.communicate()
            if p.returncode != 0:
                sys.exit(p.returncode)


def setup():
    parser = ArgumentParser(description='Create starting configs for a slimta instance.')
    parser.add_argument('--version', action='version', version='%(prog)s '+__version__)
    parser.add_argument('-f', '--force', action='store_true', default=False,
                           help='Force overwriting files if destination exists. The user is prompted by default.')
    subparsers = parser.add_subparsers(help='Sub-command Help')

    config_parser = subparsers.add_parser('config', help='Setup Configuration')
    config_parser.add_argument('-e', '--etc-dir', metavar='DIR', default=None,
                           help='Place new configs in DIR. By default, this script will prompt the user for a directory.')
    config_parser.set_defaults(action='config')

    init_parser = subparsers.add_parser('init', help='Setup Init Scripts')
    init_parser.add_argument('-t', '--type', required=True, choices=['lsb', 'systemd'],
                           help='Type of init script to create.')
    init_parser.add_argument('-n', '--name', metavar='NAME', default='slimta',
                           help='Use NAME as the name of the service, default \'%(default)s\'.')
    init_parser.add_argument('-c', '--config-file', metavar='FILE', required=True,
                           help='Use FILE as the slimta configuration file in the init script.')
    init_parser.add_argument('-d', '--daemon', required=True,
                           help='Use DAEMON as the command to execute in the init script.')
    init_parser.add_argument('--init-dir', metavar='DIR', default=None,
                           help='Put resulting init script in DIR instead of the system default.')
    init_parser.add_argument('--pid-dir', metavar='DIR', default='/var/run',
                           help='Put pid files in DIR, default %(default)s.')
    init_parser.add_argument('--enable', action='store_true',
                           help='Once the init script is created, enable it.')
    init_parser.set_defaults(action='init')

    args = parser.parse_args()

    if args.action == 'config':
        _setup_configs(args)
    elif args.action == 'init':
        _setup_inits(args)


# vim:et:fdm=marker:sts=4:sw=4:ts=4
