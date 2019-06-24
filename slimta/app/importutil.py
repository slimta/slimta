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

from importlib import import_module


def import_symbol(path):
    module_name, _, symbol_name = path.rpartition(':')
    if not module_name:
        module_name, _, symbol_name = path.rpartition('.')
    if not module_name:
        module_name, symbol_name = path, ''
    mod = import_module(module_name)
    if symbol_name:
        try:
            return getattr(mod, symbol_name)
        except AttributeError:
            raise ImportError('cannot import name ' + symbol_name)
    else:
        return mod


def custom_factory(options, *extra):
    factory = import_symbol(options.factory)
    return factory(options, *extra)


# vim:et:fdm=marker:sts=4:sw=4:ts=4
