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

from collections.abc import Mapping, Sequence


class ConfigValidationError(Exception):

    def __init__(self, msg, stack=None):
        if stack:
            msg += ' in config '+self._repr_stack(stack)
        super(ConfigValidationError, self).__init__(msg)

    def _repr_stack(self, stack):
        ret = []
        for item in stack:
            if isinstance(item, int):
                ret[-1] += '[{0}]'.format(item)
            else:
                ret.append(item)
        return '.'.join(ret)


class ConfigValidation(object):

    def __init__(self, cfg):
        self.cfg = cfg

    def _check_ref(self, section, name):
        return name in self.cfg[section]

    def _check_keys(self, opts, keydict, stack, only_keys=False):
        for k, v in opts.items():
            if k not in keydict:
                if only_keys:
                    msg = "Unexpected key '{0}'".format(k)
                    raise ConfigValidationError(msg, stack)
                else:
                    continue
            if not isinstance(v, keydict[k][0]):
                type_name = keydict[k][0].__name__.lower()
                msg = "Expected key '{0}' to be {1}".format(k, type_name)
                raise ConfigValidationError(msg, stack)
            del keydict[k]
        for k, v in keydict.items():
            if v[1]:
                msg = "Missing required key '{0}'".format(k)
                raise ConfigValidationError(msg, stack)

    def _check_process(self, opts, stack):
        keydict = {'daemon': (bool, False),
                   'hostname': (str, False),
                   'fqdn': (str, False),
                   'pid_file': (str, False),
                   'user': (str, False),
                   'group': (str, False),
                   'stdout': (str, False),
                   'stderr': (str, False),
                   'logging': (Mapping, False)}
        self._check_keys(opts, keydict, stack, True)

    def _check_lookup(self, opts, stack):
        keydict = {'type': (str, True)}
        self._check_keys(opts, keydict, stack)

    def _check_listener(self, opts, stack):
        keydict = {'type': (str, False),
                   'interface': (str, False),
                   'port': (int, False),
                   'path': (str, False),
                   'factory': (str, False)}
        self._check_keys(opts, keydict, stack, True)
        if opts.get('type') == 'custom' and not opts.get('factory'):
            msg = "The 'factory' key must be given when using 'custom' type"
            raise ConfigValidationError(msg, stack)

    def _check_edge(self, opts, stack):
        keydict = {'type': (str, True),
                   'queue': (str, True),
                   'factory': (str, False),
                   'listener': (Mapping, False),
                   'listeners': (Sequence, False),
                   'hostname': (str, False),
                   'max_size': (int, False),
                   'tls': (Mapping, False),
                   'tls_immediately': (bool, False),
                   'proxyprotocol': (bool, False),
                   'rules': (Mapping, False)}
        self._check_keys(opts, keydict, stack)
        if not self._check_ref('queue', opts.queue):
            msg = "No match for reference key 'queue'"
            raise ConfigValidationError(msg, stack)
        if opts.type == 'custom' and not opts.get('factory'):
            msg = "The 'factory' key must be given when using 'custom' type"
            raise ConfigValidationError(msg, stack)
        if 'listeners' in opts:
            if 'listener' in opts:
                msg = "Cannot use both 'listener' and 'listeners' keys"
                raise ConfigValidationError(msg, stack)
            for i, listener in enumerate(opts.get('listeners')):
                self._check_listener(listener, stack+['listeners', i])
        elif 'listener' in opts:
            self._check_listener(opts.listener, stack+['listener'])
        if 'tls' in opts:
            tls_keydict = {'certfile': (str, True),
                           'keyfile': (str, True),
                           'ca_certs': (str, False)}
            self._check_keys(opts.tls, tls_keydict, stack+['tls'])
        if 'rules' in opts:
            rules_keydict = {'banner': (str, False),
                             'dnsbl': ((str, Sequence), False),
                             'reject_spf': (Sequence, False),
                             'lookup_senders': (Mapping, False),
                             'lookup_recipients': (Mapping, False),
                             'only_senders': (Sequence, False),
                             'only_recipients': (Sequence, False),
                             'regex_senders': (Sequence, False),
                             'regex_recipients': (Sequence, False),
                             'lookup_credentials': (Mapping, False),
                             'password_hash': (str, False),
                             'reject_spam': (Mapping, False)}
            self._check_keys(opts.rules, rules_keydict, stack+['rules'], True)
            if 'lookup_sender' in opts.rules:
                self._check_lookup(opts.rules.lookup_sender,
                                   stack+['lookup_sender'])
            if 'lookup_recipients' in opts.rules:
                self._check_lookup(opts.rules.lookup_recipients,
                                   stack+['lookup_recipients'])
            if 'lookup_credentials' in opts.rules:
                self._check_lookup(opts.rules.lookup_credentials,
                                   stack+['lookup_credentials'])

    def _check_queue(self, opts, stack):
        keydict = {'type': (str, True),
                   'relay': (str, False),
                   'factory': (str, False),
                   'bounce_queue': (str, False),
                   'retry': (Mapping, False),
                   'policies': (Sequence, False)}
        self._check_keys(opts, keydict, stack)
        if 'relay' in opts and not self._check_ref('relay', opts.relay):
            msg = "No match for reference key 'relay'"
            raise ConfigValidationError(msg, stack)
        if 'bounce_queue' in opts and not self._check_ref('queue',
                                                          opts.bounce_queue):
            msg = "No match for reference key 'bounce_queue'"
            raise ConfigValidationError(msg, stack)
        if opts.type == 'custom' and not opts.get('factory'):
            msg = "The 'factory' key must be given when using 'custom' type"
            raise ConfigValidationError(msg, stack)
        policies = opts.get('policies', [])
        for i, p in enumerate(policies):
            mystack = stack + ['policies', i]
            if not isinstance(p, Mapping):
                msg = 'Expected dictionary'
                raise ConfigValidationError(msg, mystack)
            self._check_keys(p, {'type': (str, True)}, mystack)
        if 'retry' in opts:
            retry_keydict = {'maximum': (int, False),
                             'delay': (str, False)}
            self._check_keys(opts.retry, retry_keydict, stack+['retry'], True)

    def _check_relay(self, opts, stack):
        keydict = {'type': (str, True),
                   'factory': (str, False),
                   'ehlo_as': (str, False),
                   'credentials': (Mapping, False),
                   'override_mx': (Mapping, False),
                   'ipv4_only': (bool, False)}
        self._check_keys(opts, keydict, stack)
        if opts.type == 'custom' and not opts.get('factory'):
            msg = "The 'factory' key must be given when using 'custom' type"
            raise ConfigValidationError(msg, stack)
        if opts.type == 'pipe':
            pipe_keydict = {'args': (list, True)}
            self._check_keys(opts, pipe_keydict, stack)
            for arg in opts.args:
                if not isinstance(arg, str):
                    msg = "All 'args' must be strings"
                    raise ConfigValidationError(msg, stack+['args'])
        if 'credentials' in opts:
            creds_keydict = {'username': (str, True),
                             'password': (str, True)}
            self._check_keys(opts.credentials, creds_keydict,
                             stack+['credentials'], True)

    def _check_toplevel(self, stack, program):
        _cfg = self.cfg
        if not isinstance(_cfg, Mapping):
            msg = 'Expected mapping'
            raise ConfigValidationError(msg, stack)

        keydict = {'process': (Mapping, True),
                   'edge': (Mapping, False),
                   'relay': (Mapping, False),
                   'queue': (Mapping, True)}
        self._check_keys(self.cfg, keydict, stack)

        for process, opts in self.cfg.process.items():
            self._check_process(opts, stack+['process', process])

        if 'edge' in self.cfg:
            for edge, opts in self.cfg.edge.items():
                self._check_edge(opts, stack+['edge', edge])

        for queue, opts in self.cfg.queue.items():
            self._check_queue(opts, stack+['queue', queue])

        if 'relay' in self.cfg:
            for relay, opts in self.cfg.relay.items():
                self._check_relay(opts, stack+['relay', relay])

        if program not in self.cfg.process:
            msg = "Missing required key '{0}'".format(program)
            raise ConfigValidationError(msg, stack+['process'])

    @classmethod
    def check(cls, cfg, program):
        return cls(cfg)._check_toplevel(['root'], program)


# vim:et:fdm=marker:sts=4:sw=4:ts=4
