# Copyright (c) 2014 Ian C. Good
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
import os.path
from contextlib import contextmanager
from collections.abc import Mapping, Sequence

import yaml

__all__ = ['try_configs']


@contextmanager
def _with_chdir(new_dir):
    old_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield old_dir
    finally:
        os.chdir(old_dir)


class _ConfigDict(dict):

    def __getattr__(self, key):
        return self[key]

    def __getitem__(self, key):
        try:
            return super(_ConfigDict, self).__getitem__(key)
        except KeyError:
            return None

    def get(self, key, default=None):
        try:
            return super(_ConfigDict, self).__getitem__(key)
        except KeyError:
            return self._build(default)

    @classmethod
    def _build(cls, orig):
        if isinstance(orig, str):
            return orig
        if isinstance(orig, Sequence):
            return [cls._build(item) for item in orig]
        elif isinstance(orig, Mapping):
            return cls.build(orig)
        return orig

    @classmethod
    def build(cls, orig):
        new = cls()
        for key, value in orig.items():
            new[key] = cls._build(value)
        return new


def _load_yaml(filename):
    class ConfigLoader(yaml.Loader):
        pass

    def yaml_include(loader, node):
        inc_file = loader.construct_scalar(node) if loader else node
        with open(inc_file, 'r') as inc_fobj:
            return yaml.load(inc_fobj, ConfigLoader)

    def yaml_getenv(loader, node):
        name = loader.construct_scalar(node) if loader else node
        try:
            return os.environ[name]
        except KeyError as exc:
            raise EnvironmentError(
                f'Missing environment variable: {name}') from exc

    ConfigLoader.add_constructor('!include', yaml_include)
    ConfigLoader.add_constructor('!env', yaml_getenv)
    loaded = yaml_include(None, filename)
    return _ConfigDict.build(loaded)


def try_configs(files):
    for config_file in files:
        config_file = os.path.expanduser(config_file)
        config_dir = os.path.abspath(os.path.dirname(config_file))
        config_base = os.path.basename(config_file)
        if os.path.isdir(config_dir):
            with _with_chdir(config_dir):
                if os.path.exists(config_base):
                    return _load_yaml(config_base)
    return None


# vim:et:fdm=marker:sts=4:sw=4:ts=4
