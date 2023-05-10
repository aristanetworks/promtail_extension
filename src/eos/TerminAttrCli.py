#!/usr/bin/env arista-python
# ------------------------------------------------------------------------------
#  Copyright (c) 2021-2023 Arista Networks, Inc. All rights reserved.
# ------------------------------------------------------------------------------
#  Author:
#    fdk-support@arista.com
#
#  Description:
#    Example application demonstrating the libapp.subprocess module using
#     TerminAttr.
#
#    Licensed under BSD 3-clause license:
#      https://opensource.org/licenses/BSD-3-Clause
#
#  Tags:
#    license-bsd-3-clause
#
# ------------------------------------------------------------------------------

from __future__ import absolute_import, division, print_function

import json
import os
import subprocess

import CliExtension


class ShowTerminAttrStatusCmd(CliExtension.ShowCommandClass):
    def handler(self, ctx):
        result = {"running": False}
        daemon = ctx.getDaemon("TerminAttrDaemon")
        if daemon is None:
            # Daemon is not currently running
            return result
        for k, v in daemon.status.statusIter():
            result[k] = v
        result["running"] = result.get("TerminAttrDaemon") == "up"
        return result

    def render(self, data):
        for k, v in data.items():
            print(k, v)


class AddressCmd(CliExtension.CliCommandClass):
    def handler(self, ctx):
        ctx.daemon.config.configSet(
            "address",
            json.dumps([a + ":" + str(p) for a, p in zip(ctx.args["<address>"], ctx.args["<port>"])]),
        )

    def noHandler(self, ctx):
        ctx.daemon.config.configDel("address")


class AuthorizationCmd(CliExtension.CliCommandClass):
    def handler(self, ctx):
        auth = {}
        failed = False
        ca_file = ctx.args.get("<ca-file>")
        if ca_file:
            if not os.path.exists(ca_file):
                failed = True
                ctx.addError("CA file does not exist: %s" % ca_file)
        auth["ca-file"] = ca_file

        if ctx.args.get("certs"):
            auth["method"] = "certs"
            cert_file = ctx.args["<cert-file>"]
            key_file = ctx.args["<key-file>"]
            if not os.path.exists(cert_file):
                failed = True
                ctx.addError("Certificate file does not exist: %s" % cert_file)
            if not os.path.exists(key_file):
                failed = True
                ctx.addError("Key file does not exist: %s" % key_file)
            auth["cert-file"] = cert_file
            auth["key-file"] = key_file

        elif ctx.args.get("key"):
            auth["method"] = "key"
            key = ctx.args["<key>"]
            auth["key"] = key

        elif ctx.args.get("session-token"):
            auth["method"] = "session"
            session_token_file = ctx.args["<session-token-file>"]
            if not os.path.exists(session_token_file):
                failed = True
                ctx.addError("Key file does not exist: %s" % session_token_file)
            auth["session-token"] = session_token_file

        elif ctx.args.get("tls"):
            auth["method"] = "tls"

        elif ctx.args.get("token"):
            auth["method"] = "token"
            token_file = ctx.args["<token-file>"]
            auth["token-file"] = token_file

        elif ctx.args.get("token-secure"):
            auth["method"] = "token-secure"
            token_file = ctx.args["<token-file>"]
            auth["token-file"] = token_file

        if failed:
            return
        ctx.daemon.config.configSet("auth", json.dumps(auth))

    def noHandler(self, ctx):
        ctx.daemon.config.configDel("auth")


class CompressionCmd(CliExtension.CliCommandClass):
    def handler(self, ctx):
        ctx.daemon.config.configSet("compression", ctx.args.get("<compression>"))

    def noHandler(self, ctx):
        ctx.daemon.config.configDel("compression")


class TerminAttrCmd(CliExtension.CliCommandClass):
    def handler(self, ctx):
        maybe_binary = ctx.args["<binary>"]
        if not os.path.exists(maybe_binary):
            ctx.addError("Binary file does not exist: %s" % maybe_binary)
            return
        try:
            out = subprocess.check_output([maybe_binary, "-version"])
        except OSError as e:
            ctx.addError("OSError occurred whilst trying to check version." " Is this a valid binary? {}".format(e))
            return
        except subprocess.CalledProcessError as e:
            ctx.addError(
                "CalledProcessError occurred whilst trying to check version." " Is this a valid binary? {}".format(e)
            )
            return

        # Check that the version string contains the go version it was built with
        if not out.contains(" go1"):
            ctx.addWarning("This may not be a valid TerminAttr command - will attempt to use anyway")
        ctx.daemon.config.configSet("terminattr", maybe_binary)

    def noHandler(self, ctx):
        ctx.daemon.config.configDel("terminattr")

    defaultHandler = noHandler


class VrfCmd(CliExtension.CliCommandClass):
    def handler(self, ctx):
        ctx.daemon.config.configSet("vrf", ctx.args.get("<vrf>"))

    def noHandler(self, ctx):
        ctx.daemon.config.configDel("vrf")


class DisabledCmd(CliExtension.CliCommandClass):
    def handler(self, ctx):
        ctx.daemon.config.disable()

    def noHandler(self, ctx):
        ctx.daemon.config.enable()

    defaultHandler = handler


def Plugin(ctx):  # pylint: disable=unused-argument
    CliExtension.registerCommand("showTerminAttrStatus", ShowTerminAttrStatusCmd, namespace="fdk.terminattr")
    CliExtension.registerCommand("address", AddressCmd, namespace="fdk.terminattr")
    CliExtension.registerCommand("authorization", AuthorizationCmd, namespace="fdk.terminattr")
    CliExtension.registerCommand("compression", CompressionCmd, namespace="fdk.terminattr")
    CliExtension.registerCommand("vrf", VrfCmd, namespace="fdk.terminattr")
    CliExtension.registerCommand("terminattr", TerminAttrCmd, namespace="fdk.terminattr")
    CliExtension.registerCommand("disabled", DisabledCmd, namespace="fdk.terminattr")
