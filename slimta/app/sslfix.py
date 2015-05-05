# Copyright (c) 2012 Ian C. Good
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

"""Python 2.7.9 removed a private library function that gevent was depending
on. Importing this module checks for ``ssl._ssl.sslwrap`` and re-adds an
equivalent if it is missing, until gevent is compatible with Python 2.7.9+.

This code was shamelessly stolen from `this gevent issue
<https://github.com/gevent/gevent/issues/477>`_.

.. warning:: This module may be removed once compatibility is restored.

"""

from __future__ import absolute_import

import inspect
__ssl__ = __import__('ssl')

try:
    _ssl = __ssl__._ssl
except AttributeError:
    _ssl = __ssl__._ssl2


def new_sslwrap(sock, server_side=False, keyfile=None, certfile=None,
                cert_reqs=__ssl__.CERT_NONE,
                ssl_version=__ssl__.PROTOCOL_SSLv23, ca_certs=None,
                ciphers=None):
    context = __ssl__.SSLContext(ssl_version)
    context.verify_mode = cert_reqs or __ssl__.CERT_NONE
    if ca_certs:
        context.load_verify_locations(ca_certs)
    if certfile:
        context.load_cert_chain(certfile, keyfile)
    if ciphers:
        context.set_ciphers(ciphers)

    caller_self = inspect.currentframe().f_back.f_locals['self']
    return context._wrap_socket(sock, server_side=server_side,
                                ssl_sock=caller_self)

if not hasattr(_ssl, 'sslwrap'):
    _ssl.sslwrap = new_sslwrap


# vim:et:fdm=marker:sts=4:sw=4:ts=4
