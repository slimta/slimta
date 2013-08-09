#### [Project Homepage][1]
#### [Usage Manual][2]

--------------------

About
=====

`slimta` is a configurable MTA based on the `python-slimta` libraries. While
the purpose of the `python-slimta` library is to avoid configuration files and
allow full control via Python code, the `slimta` project recognizes that not
everyone will want or need that level of control. Setup, configuration, and
execution of `slimta` is designed to be familiar to non-programmers. 

The `slimta` project is released under the [MIT License][3].

Getting Started
===============

Install `slimta` from [PyPi][4]:

    $ sudo pip install slimta

Pip should pull in all the required dependencies. Next, we create the basic
configuration files:

    $ slimta-setup

This creates 3 files, in `~/.slimta/` or wherever you specified. The sample
configs are designed to work out of the box, so lets give it a shot:

    $ slimta

In another terminal, let's connect to port 1025 to see if it's working. After
the banner (the line beginning with `220 `), type in `QUIT` to end the session:

    $ telnet localhost 1025
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.
    220 localhost.localdomain ESMTP example.com Mail Delivery Agent
    QUIT
    221 2.0.0 Bye
    Connection closed by foreign host.

Port 1025 is fully capable of accepting mail in the SMTP session, but is
configured by default with the `blackhole` relay to silently discard messages.
You can also try it out with the built-in Python SMTP libraries:

    $ python
    >>> import smtplib
    >>> smtplib.SMTP('localhost', 1025).sendmail('test@example.com',
                                                 ['postmaster@example.com'],
                                                 'test message')

At this point, we're still a little ways off from where you'd probably like to
be: actually sending and receiving email to the Internet. Please check out the
[Usage Manual][2] for information on configuring `slimta` to your liking,
including more advanced and custom setups.

[1]: http://slimta.org/
[2]: http://docs.slimta.org/en/latest/manual/slimta.html
[3]: http://opensource.org/licenses/MIT
[4]: https://pypi.python.org/pypi/slimta/

