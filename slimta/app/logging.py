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

import sys
import logging
import logging.config

from config import Mapping, Sequence


def _flatten(val):
    if isinstance(val, Mapping):
        new_dict = {}
        for k, v in val.iteritems():
            new_dict[k] = _flatten(v)
        return new_dict
    elif isinstance(val, Sequence):
        new_list = []
        for v in val:
            new_list.append(_flatten(v))
        return new_list
    else:
        return val


def setup_logging(settings):
    if settings:
        logging.config.dictConfig(_flatten(settings))
    else:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)


# vim:et:fdm=marker:sts=4:sw=4:ts=4
