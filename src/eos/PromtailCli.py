#!/usr/bin/env arista-python
# ------------------------------------------------------------------------------
#  Copyright (c) 2021-2023 Arista Networks, Inc. All rights reserved.
# ------------------------------------------------------------------------------
#  Author:
#    fdk-support@arista.com
#
#  Description:
#    Example application demonstrating the libapp.subprocess module using
#     Promtail.
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


class ShowPromtailStatusCmd(CliExtension.ShowCommandClass):
    def handler(self, ctx):
        result = {"running": False}
        daemon = ctx.getDaemon("PromtailDaemon")
        if daemon is None:
            # Daemon is not currently running
            return result
        for k, v in daemon.status.statusIter():
            result[k] = v
        result["running"] = result.get("PromtailDaemon") == "up"
        return result

    def render(self, data):
        for k, v in data.items():
            print(k, v)


class DestinationCmd(CliExtension.CliCommandClass):
    def handler(self, ctx):
        ctx.daemon.config.configSet("destination", ctx.args["<destination>"])

    def noHandler(self, ctx):
        ctx.daemon.config.configDel("destination")


class BinaryCmd(CliExtension.CliCommandClass):
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
            ctx.addWarning("This may not be a valid Promtail command - will attempt to use anyway")
        ctx.daemon.config.configSet("promtail", maybe_binary)

    def noHandler(self, ctx):
        ctx.daemon.config.configDel("promtail")

    defaultHandler = noHandler


class DisabledCmd(CliExtension.CliCommandClass):
    def handler(self, ctx):
        ctx.daemon.config.disable()

    def noHandler(self, ctx):
        ctx.daemon.config.enable()

    defaultHandler = handler


def Plugin(ctx):  # pylint: disable=unused-argument
    CliExtension.registerCommand("showPromtailStatus", ShowPromtailStatusCmd, namespace="fdk.promtail")
    CliExtension.registerCommand("destination", DestinationCmd, namespace="fdk.promtail")
    CliExtension.registerCommand("binary", BinaryCmd, namespace="fdk.promtail")
    CliExtension.registerCommand("disabled", DisabledCmd, namespace="fdk.promtail")
