# Copyright (c) 2017 Ian C. Good
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

import socket

from slimta.util import create_listeners

from .importutil import custom_factory
from .validation import ConfigValidationError


class Listeners(object):

    cache = {}

    def __init__(self, edge_options, default_port):
        if 'listeners' in edge_options:
            self.listeners = edge_options.listeners
        else:
            self.listeners = [edge_options.get('listener', {})]
        self.default_port = default_port

    @classmethod
    def _get_cached_listeners(cls, options):
        key = hash(tuple(options.items()))
        if key in cls.cache:
            listeners = cls.cache[key][:]
            for i, listener in enumerate(listeners):
                if isinstance(listener, socket.socket):
                    fd = listener.fileno()
                    family = listener.family
                    socktype = listener.type
                    proto = listener.proto
                    listeners[i] = socket.fromfd(fd, family, socktype, proto)
            return listeners

    @classmethod
    def _set_cached_listeners(cls, options, listeners):
        key = hash(tuple(options.items()))
        cls.cache[key] = listeners

    def _get_listener_type(self, options):
        if 'type' in options:
            return options.type
        elif 'path' in options:
            return 'unix'
        elif 'factory' in options:
            return 'custom'
        else:
            return 'tcp'

    def _get_socket_family(self, type):
        if type in ('tcp', 'udp'):
            return socket.AF_UNSPEC
        elif type in ('tcp4', 'udp4'):
            return socket.AF_INET
        elif type in ('tcp6', 'udp6'):
            return socket.AF_INET6
        elif type == 'unix':
            return socket.AF_UNIX

    def _get_socket_type(self, type):
        if type in ('tcp', 'tcp4', 'tcp6', 'unix'):
            return socket.SOCK_STREAM
        elif type in ('udp', 'udp4', 'udp6'):
            return socket.SOCK_DGRAM

    def _get_socket_bind_address(self, type, options):
        if type in ('tcp', 'tcp4', 'tcp6', 'udp', 'udp4', 'udp6'):
            port = int(options.get('port', self.default_port))
            return (options.interface or None, port)
        elif type == 'unix':
            return options.path

    def _get_listeners(self, type, options):
        family = self._get_socket_family(type)
        socktype = self._get_socket_type(type)
        if type in ('tcp', 'tcp4', 'tcp6', 'udp', 'udp4', 'udp6', 'unix'):
            address = self._get_socket_bind_address(type, options)
            return create_listeners(address, family=family, socktype=socktype)
        elif type == 'custom':
            return [custom_factory(options)]
        else:
            msg = 'listener type does not exist: ' + type
            raise ConfigValidationError(msg)

    def _get_all(self):
        for options in self.listeners:
            listeners = self._get_cached_listeners(options)
            if listeners is None:
                type = self._get_listener_type(options)
                listeners = self._get_listeners(type, options)
                self._set_cached_listeners(options, listeners)
            for listener in listeners:
                yield listener

    def __iter__(self):
        return self._get_all()


# vim:et:fdm=marker:sts=4:sw=4:ts=4
