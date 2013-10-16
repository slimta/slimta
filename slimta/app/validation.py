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

from config import Mapping, Sequence


class ConfigValidationError(Exception):

    def __init__(self, msg, stack):
        final = msg + ' in config '+self._repr_stack(stack)
        super(ConfigValidationError, self).__init__(final)

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

    def _check_ref(self, path, name):
        try:
            resolved_path = self.cfg.getByPath(path)
            return name in resolved_path
        except AttributeError:
            return False

    def _check_keys(self, opts, keydict, stack, only_keys=False):
        for k, v in opts.iteritems():
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
        for k, v in keydict.iteritems():
            if v[1]:
                msg = "Missing required key '{0}'".format(k)
                raise ConfigValidationError(msg, stack)

    def _check_process(self, opts, stack):
        if stack[-1] not in ('slimta', 'worker'):
            msg = "Unexpected process type '{0}'".format(stack[-1])
            raise ConfigValidationError(msg, stack[:-1])
        keydict = {'daemon': (bool, False),
                   'user': (basestring, False),
                   'group': (basestring, False),
                   'stdout': (basestring, False),
                   'stderr': (basestring, False),
                   'logging': (Mapping, False)}
        self._check_keys(opts, keydict, stack, True)

    def _check_edge(self, opts, stack):
        keydict = {'type': (basestring, True),
                   'queue': (basestring, True),
                   'factory': (basestring, False),
                   'listener': (Mapping, False),
                   'hostname': (basestring, False),
                   'max_size': (int, False),
                   'tls': (Mapping, False),
                   'tls_immediately': (bool, False),
                   'rules': (Mapping, False)}
        self._check_keys(opts, keydict, stack)
        if not self._check_ref('queue', opts.queue):
            msg = "No match for reference key 'queue'"
            raise ConfigValidationError(msg, stack)
        if opts.type == 'custom' and not opts.get('factory'):
            msg = "The 'factory' key must be given when using 'custom' type"
            raise ConfigValidationError(msg, stack)
        if 'listener' in opts:
            listener_keydict = {'interface': (basestring, False),
                                'port': (int, False)}
            self._check_keys(opts.listener, listener_keydict,
                             stack+['listener'], True)
        if 'tls' in opts:
            tls_keydict = {'certfile': (basestring, True),
                           'keyfile': (basestring, True)}
            self._check_keys(opts.tls, tls_keydict, stack+['tls'])
        if 'rules' in opts:
            rules_keydict = {'banner': (basestring, False),
                             'dnsbl': (basestring, False),
                             'reject_spf': (Sequence, False),
                             'only_senders': (Sequence, False),
                             'only_recipients': (Sequence, False),
                             'require_credentials': (Mapping, False),
                             'scan': (Mapping, False)}
            self._check_keys(opts.rules, rules_keydict, stack+['rules'], True)

    def _check_queue(self, opts, stack):
        keydict = {'type': (basestring, True),
                   'relay': (basestring, False),
                   'factory': (basestring, False),
                   'policies': (Sequence, False)}
        self._check_keys(opts, keydict, stack)
        if 'relay' in opts and not self._check_ref('relay', opts.relay):
            msg = "No match for reference key 'relay'"
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
            self._check_keys(p, {'type': (basestring, True)}, mystack)
        if 'retry' in opts:
            retry_keydict = {'maximum': (int, False),
                             'delay': (basestring, False)}
            self._check_keys(opts.retry, retry_keydict, stack+['retry'], True)

    def _check_relay(self, opts, stack):
        keydict = {'type': (basestring, True),
                   'factory': (basestring, False),
                   'ehlo_as': (basestring, False),
                   'credentials': (Mapping, False)}
        self._check_keys(opts, keydict, stack)
        if opts.type == 'custom' and not opts.get('factory'):
            msg = "The 'factory' key must be given when using 'custom' type"
            raise ConfigValidationError(msg, stack)
        if 'credentials' in opts:
            creds_keydict = {'username': (basestring, True),
                             'password': (basestring, True)}
            self._check_keys(opts.credentials, creds_keydict,
                             stack+['credentials'], True)

    def _check_toplevel(self, stack, program):
        keydict = {'process': (Mapping, True),
                   'edge': (Mapping, False),
                   'relay': (Mapping, False),
                   'queue': (Mapping, True),
                   'celery_app': (Mapping, False)}
        self._check_keys(self.cfg, keydict, stack)

        for process, opts in self.cfg.process.iteritems():
            self._check_process(opts, stack+['process', process])

        if 'edge' in self.cfg:
            for edge, opts in self.cfg.edge.iteritems():
                self._check_edge(opts, stack+['edge', edge])

        for queue, opts in self.cfg.queue.iteritems():
            self._check_queue(opts, stack+['queue', queue])

        if 'relay' in self.cfg:
            for relay, opts in self.cfg.relay.iteritems():
                self._check_relay(opts, stack+['relay', relay])

        if program not in self.cfg.process:
            msg = "Missing required key '{0}'".format(program)
            raise ConfigValidationError(msg, stack+['process'])

    @classmethod
    def check(cls, cfg, program):
        return cls(cfg)._check_toplevel(['root'], program)


# vim:et:fdm=marker:sts=4:sw=4:ts=4
