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

from promtail import libapp


class ShowPromtailStatusCmd(libapp.cli.ShowEnabledBaseCmd):
    daemon = "PromtailDaemon"

    def handler(self, ctx):
        result = super(ShowPromtailStatusCmd, self).handler(ctx)
        result["status"] = {}

        daemon = ctx.getDaemon("PromtailDaemon")

        if daemon is None:
            # Daemon is not currently running
            return result

        status = libapp.cli.StatusAccessor(daemon.status)

        result["status"]["promtail"] = status.get("Promtail")
        result["status"]["destination"] = status.get("destination")
        result["status"]["binary"] = status.get("binary")

        return result

    def render(self, data):
        super(ShowPromtailStatusCmd, self).render(data)
        print("Promtail status store:")
        for k, v in data["status"].items():
            print("  {}\t{}".format(k, v))


class DestinationCmd(libapp.cli.ConfigCommandClass):
    key_syntax = "destination"


class BinaryCmd(libapp.cli.ConfigCommandClass):
    key_syntax = "binary"

    def handler(self, ctx):
        maybe_binary = ctx.args["<binary>"]
        if not os.path.exists(maybe_binary):
            ctx.addError("Binary file does not exist: %s" % maybe_binary)
            return
        try:
            out = subprocess.check_output([maybe_binary, "-version"]).decode("utf-8")
        except OSError as e:
            ctx.addError("OSError occurred whilst trying to check version." " Is this a valid binary? {}".format(e))
            return
        except subprocess.CalledProcessError as e:
            ctx.addError(
                "CalledProcessError occurred whilst trying to check version." " Is this a valid binary? {}".format(e)
            )
            return

        # Check that the version string contains the go version it was built with
        if " go1" not in out:
            ctx.addWarning("This may not be a valid Promtail command - will attempt to use anyway")

        super(BinaryCmd, self).handler(ctx)

    def noHandler(self, ctx):
        super(BinaryCmd, self).noHandler(ctx)

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
