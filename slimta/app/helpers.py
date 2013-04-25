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


from functools import wraps
from socket import getfqdn

from slimta.edge.smtp import SmtpValidators
from slimta.smtp.auth import Auth, CredentialsInvalidError
from slimta.util.dnsbl import check_dnsbl

from slimta.policy.forward import Forward
from slimta.policy.split import RecipientSplit, RecipientDomainSplit
from slimta.policy.spamassassin import SpamAssassin
from slimta.policy.headers import AddDateHeader, AddMessageIdHeader, \
                                  AddReceivedHeader


class RuleHelpers(object):

    @staticmethod
    def _noop_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper

    def __init__(self, options):
        rules = options.get('rules', {})
        self.banner = rules.get('banner')
        if self.banner:
            self.banner = self.banner.format(fqdn=getfqdn())
        self.dnsbl = rules.get('dnsbl')
        self.only_senders = rules.get('only_senders')
        self.only_rcpts = rules.get('only_recipients')
        self.credentials = rules.get('require_credentials')

    def is_sender_ok(self, validators, sender):
        if self.only_senders is not None and sender not in self.only_senders:
            return False
        if self.credentials is not None and not validators.session.auth_result:
            return False
        return True

    def is_recipient_ok(self, recipient):
        if self.only_rcpts is not None and recipient not in self.only_rcpts:
            return False
        return True

    def get_banner_decorator(self):
        if self.dnsbl:
            return check_dnsbl(self.dnsbl, match_code='520')
        return self._noop_decorator

    def set_banner_message(self, reply):
        if self.banner:
            reply.message = self.banner


def build_smtpedge_validators(options):
    rules = RuleHelpers(options)
    class CustomValidators(SmtpValidators):
        @rules.get_banner_decorator()
        def handle_banner(self, reply, address):
            rules.set_banner_message(reply)
        def handle_mail(self, reply, sender):
            if not rules.is_sender_ok(self, sender):
                reply.code = '550'
                reply.message = '5.7.1 Sender <{0}> Not allowed'.format(sender)
        def handle_rcpt(self, reply, rcpt):
            if not rules.is_recipient_ok(rcpt):
                reply.code = '550'
                reply.message = '5.7.1 Recipient <{0}> Not allowed'.format(rcpt)
    return CustomValidators


def build_smtpedge_auth(options):
    rules = RuleHelpers(options)
    if rules.credentials is None:
        return None
    class CustomAuth(Auth):
        def verify_secret(self, username, password, identity=None):
            try:
                assert rules.credentials[username] == password
            except (KeyError, AssertionError):
                raise CredentialsInvalidError()
            return username
        def get_secret(self, username, identity=None):
            try:
                return rules.credentials[username], username
            except KeyError:
                raise CredentialsInvalidError()
    return CustomAuth


def add_queue_policies(queue, policy_options):
    for policy in policy_options:
        if policy.type == 'add_date_header':
            queue.add_policy(AddDateHeader())
        elif policy.type == 'add_messageid_header':
            queue.add_policy(AddMessageIdHeader())
        elif policy.type == 'add_received_header':
            queue.add_policy(AddReceivedHeader())
        elif policy.type == 'recipient_split':
            queue.add_policy(RecipientSplit())
        elif policy.type == 'recipient_domain_split':
            queue.add_policy(RecipientDomainSplit())
        elif policy.type == 'forward':
            forward = Forward()
            for pattern, repl in dict(policy.get('mappings', {})).items():
                forward.add_mapping(pattern, reply)
            queue.add_policy(forward)
        elif policy.type == 'spamassassin':
            host = policy.get('host', 'localhost')
            port = int(policy.get('port', 783))
            queue.add_policy(SpamAssassin((host, port)))


# vim:et:fdm=marker:sts=4:sw=4:ts=4
