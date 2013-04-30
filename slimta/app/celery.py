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

from celery.loaders.app import AppLoader
from celery import Celery
from celery.datastructures import DictAttribute


def _get_loader_class(settings):
    class MyLoader(AppLoader):
        def read_configuration(self):
            if settings:
                return DictAttribute(settings)
            return {}
    return MyLoader


def _set_custom_defaults(settings):
    if 'CELERYD_POOL' not in settings:
        settings['CELERYD_POOL'] = 'gevent'
    if 'CELERYD_CONCURRENCY' not in settings:
        settings['CELERYD_CONCURRENCY'] = 50


def get_celery_app(cfg):
    settings = cfg.get('celery_app')
    _set_custom_defaults(settings)
    loader_cls = _get_loader_class(settings)
    return Celery('slimta.app.queue', loader=loader_cls)


# vim:et:fdm=marker:sts=4:sw=4:ts=4
