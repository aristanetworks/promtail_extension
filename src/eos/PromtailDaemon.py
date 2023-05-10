#!/usr/bin/env python3
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
import sys

import eossdk
from promtail.libapp import eossdk_utils
from promtail.libapp.subprocess import SubprocessHandler, SubprocessMgr


class PromtailDaemon(  # pylint: disable=too-many-instance-attributes
    eossdk_utils.EosSdkAgent, eossdk.AgentHandler, SubprocessHandler
):
    def __init__(self, sdk):
        self.agent_mgr = sdk.get_agent_mgr()
        self.subprocess_mgr = SubprocessMgr()
        eossdk.AgentHandler.__init__(self, self.agent_mgr)
        SubprocessHandler.__init__(self, self.subprocess_mgr)

        self.initialized = False
        self.tracer = eossdk.Tracer("PromtailDaemon")
        self.tracer.enabled_is(0, True)

        self.child = None
        self.promtail = ["Promtail"]  # type: list[str]

        self.addresses = []  # type: list[str]
        self.auth = []  # type: list[str]
        self.compression = []  # type: list[str]
        self.vrf = []  # type: list[str]

    # inherited from AgentHandler
    # http://aristanetworks.github.io/EosSdk/docs/2.10.0/ref/agent.html
    def on_initialized(self):
        """Handler called after the agent has been internally initialized.
        At this point, all managers have synchronized with Sysdb, and the
        agent's handlers will begin firing. In the body of this method, agents
        should check Sysdb and handle the initial state of any configuration and
        status that this agent is interested in."""
        self.tracer.trace0("on_initialized")

        for k in self.agent_mgr.agent_option_iter():
            self.on_agent_option(k, self.agent_mgr.agent_option(k))

        self.tracer.trace0("{}".format(tuple(self.agent_mgr.agent_option_iter())))

        self.agent_mgr.status_set("PromtailDaemon", "up")

        self.initialized = True
        self.run_agent()
        self.tracer.trace2("initialized")

    def run_agent(self):
        # If we're still initializing, don't actually run the daemon
        if not self.initialized:
            return

        # There was an existing child process - we should terminate it
        if self.child:
            child = self.child
            self.child = None
            child.kill()
            self.agent_mgr.status_set("Promtail", "down")

        args = self.promtail + self.addresses + self.auth + self.compression + self.vrf

        self.tracer.trace0("run_agent -- {}".format(" ".join(args)))
        self.child = self.subprocess_mgr.run(args)
        self.agent_mgr.status_set("Promtail", "up")

    def on_process_exit(self, child, exit_code):
        """Handler called when a child process exits.
        This is used to determine when the promtail process exits."""
        self.tracer.trace3("on_process_exit({}, {})".format(child, exit_code))
        if child == self.child:
            self.child = None
            self.agent_mgr.status_set("Promtail", "down")

    def handle_address(self, value):
        addresses = ""  # type: list[str]|str

        try:
            addresses = json.loads(value)  # type: list[str]|str
        except ValueError:
            pass
        if isinstance(addresses, list):
            addresses = ",".join(addresses)

        if addresses:
            addresses = ["-cvaddr", addresses]
        else:
            addresses = []

        self.addresses = addresses

    def handle_authentication(self, value):
        auth = "none"

        try:
            auth = json.loads(value)
        except ValueError:
            pass
        if isinstance(auth, dict):
            ca_file = auth.get("ca-file")

            method = auth["method"]
            if method == "certs":
                auth = ",".join(
                    (
                        "certs",
                        auth["cert-file"],
                        auth["key-file"],
                    )
                )
            elif method == "key":
                auth = ",".join(
                    (
                        "key",
                        auth["key"],
                    )
                )
            elif method == "session":
                auth = ",".join(
                    (
                        "session-token",
                        auth["session-token"],
                    )
                )
            elif method == "tls":
                auth = "none-tls"
            elif method == "token":
                auth = ",".join(
                    (
                        "token",
                        auth["token-file"],
                    )
                )
            elif method == "token-secure":
                auth = ",".join(
                    (
                        "token-secure",
                        auth["token-file"],
                    )
                )

            if ca_file:
                auth += "," + ca_file

        if auth:
            auth = ["-cvauth", auth]
        else:
            auth = []

        self.auth = auth

    def handle_compression(self, value):
        if value:
            self.compression = ["-cvcompression", value]
        else:
            self.compression = []

    def handle_vrf(self, value):
        if value:
            self.vrf = ["-cvvrf", value]
        else:
            self.vrf = []

    def handle_promtail(self, value):
        if value:
            self.promtail = [value]
        else:
            self.promtail = ["Promtail"]

    def on_agent_option(self, key, val):
        """Handler called when a configuration option of the agent has changed.
        If the option was deleted, this will be called with value set as the
        empty string. Otherwise, value will contain the added or altered string
        corresponding to the option name."""
        self.tracer.trace0("on_agent_option({}, {})".format(key, val))

        if key == "address":
            self.handle_address(val)
        elif key == "auth":
            self.handle_authentication(val)
        elif key == "compression":
            self.handle_compression(val)
        elif key == "vrf":
            self.handle_vrf(val)
        elif key == "promtail":
            self.handle_promtail(val)

        self.run_agent()
        self.agent_mgr.status_set(key, val)

    def on_agent_enabled(self, enabled):
        self.tracer.trace3("on_agent_enabled({})".format(enabled))
        # Make sure that Promtail is killed
        if self.child:
            child = self.child
            self.child = None
            child.kill()
            self.agent_mgr.status_set("Promtail", "down")
        self.agent_mgr.status_del("PromtailDaemon")
        self.agent_mgr.agent_shutdown_complete_is(True)


def main():
    sdk = eossdk.Sdk("PromtailDaemon")
    _ = PromtailDaemon(sdk)
    sdk.main_loop(sys.argv)


if __name__ == "__main__":
    main()
