# www

Static web server

[![download](https://img.shields.io/github/v/release/nbari/www)](https://github.com/nbari/www/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/nbari/www)](https://goreportcard.com/report/github.com/nbari/www)

Linux precompiled binaries

[![deb](https://img.shields.io/badge/deb-packagecloud.io-844fec.svg)](https://packagecloud.io/nbari/www)
[![rpm](https://img.shields.io/badge/rpm-packagecloud.io-844fec.svg)](https://packagecloud.io/nbari/www)

## Install on mac:

    $ brew tap nbari/homebrew-www

next

    $ brew install www

## Install on FreeBSD:

To install the port:

    $ cd /usr/ports/www/go-www/ && make install clean

To add the package:

    $ pkg install go-www


# Why ?

Because of the need to share, test via HTTP the contents of a directory.


# How it works

By typing ``www`` will start a web server and use as a document root the
directory where the command was call, a different document root may be specified
by using the ``-r`` option, for example:

    $ www -r /tmp

By default  **www** listen on port 8000, this can be changed by using the ``-p`` option:

    $ www -p 80 (may need root privilages)


If TLS is required use the option `-s` and a domain name, for example:

    $ www -s example.com

This will try to get a valid certificate by using letsencrypt but the port will always be 443

When using the ``-s`` use ``https`` option on the browser.

Example using tls and document root on port 8080:

    $ www -s localhost -r /tmp -p 8080
