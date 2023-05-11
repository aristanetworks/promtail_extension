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

import logging
import json
import os
import socket
import sys
import tempfile

import eossdk

import libapp
import libapp.eossdk_utils
import libapp.daemon
from promtail.libapp.subprocess import SubprocessHandler, SubprocessMgr

# We have a .zip file locally with our dependencies, build by the makefile.
# This is required for pyyaml
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "python_deps" + str(sys.version_info[0]) + ".zip"),
)

import yaml

logging.basicConfig(level=logging.DEBUG)

daemon_name = "PromtailDaemon"

logger = logging.getLogger(__name__)


class PromtailDaemon(  # pylint: disable=too-many-instance-attributes
    libapp.eossdk_utils.EosSdkAgent,
    libapp.daemon.ConfigMixin,
    libapp.daemon.StatusMixin,
    eossdk.AgentHandler,
    SubprocessHandler,
):
    def __init__(self, sdk):
        self.agent_mgr = sdk.get_agent_mgr()
        self.subprocess_mgr = SubprocessMgr()
        eossdk.AgentHandler.__init__(self, self.agent_mgr)
        SubprocessHandler.__init__(self, self.subprocess_mgr)

        self.initialized = False

        self.promtail_config = tempfile.NamedTemporaryFile(
            mode="w+", encoding="utf-8", dir="/tmp/", prefix="promtail-", suffix=".yaml"
        )

        self.child = None
        self.binary = ["/opt/apps/promtail/promtail"]  # type: list[str]
        self.destination = None

        self.addresses = []  # type: list[str]

    # inherited from AgentHandler
    # http://aristanetworks.github.io/EosSdk/docs/2.10.0/ref/agent.html
    def on_initialized(self):
        """Handler called after the agent has been internally initialized.
        At this point, all managers have synchronized with Sysdb, and the
        agent's handlers will begin firing. In the body of this method, agents
        should check Sysdb and handle the initial state of any configuration and
        status that this agent is interested in."""
        logger.debug("on_initialized")

        # Remove all status, giving us a clean slate.
        self.status.clear()

        # Load any initial config.
        for item in self.config:
            self.on_agent_config(item)

        # Indicate the daemon status (read by the CLI code).
        self.status["running"] = True

        self.initialized = True

        self.run_agent()
        logger.debug("initialized")

    def write_config(self):
        config = {
            "server": {"http_listen_port": 0, "grpc_listen_port": 0},
            "positions": {"filename": "/tmp/positions.yaml"},
            "scrape_configs": [
                {
                    "job_name": "system",
                    "pipeline_stages": None,
                    "static_configs": [
                        {
                            "labels": {
                                "job": "agent_logs",
                                "host": socket.gethostname(),
                                "__path__": "/var/log/agents-latest/*",
                            }
                        }
                    ],
                }
            ],
        }
        if self.destination:
            config["clients"] = [{"url": self.destination}]

        self.promtail_config.seek(0)
        self.promtail_config.write(yaml.dump(config))
        self.promtail_config.truncate()
        self.promtail_config.flush()

        logger.debug("Config file written to %s", self.promtail_config.name)
        logger.debug(yaml.dump(config))

    def run_agent(self):
        # If we're still initializing, don't actually run the daemon
        if not self.initialized:
            return

        if not self.destination:
            self.agent_mgr.status_set("Promtail", "No Destination Set")

        # There was an existing child process - we should terminate it
        if self.child:
            child = self.child
            self.child = None
            child.kill()
            self.agent_mgr.status_set("Promtail", "down")

        self.write_config()

        args = self.binary + ["-config.file", self.promtail_config.name]

        logger.info("run_agent -- {}".format(" ".join(args)))
        self.child = self.subprocess_mgr.run(args)
        self.agent_mgr.status_set("Promtail", "up")

    def on_process_exit(self, child, exit_code):
        """Handler called when a child process exits.
        This is used to determine when the promtail process exits."""
        logger.debug("on_process_exit({}, {})".format(child, exit_code))
        if child == self.child:
            self.child = None
            self.agent_mgr.status_set("Promtail", "down")

    def handle_destination(self, item):
        self.destination = item.value or None

    def handle_binary(self, item):
        self.binary = [item.value] or ["/opt/apps/promtail/promtail"]

    def on_agent_config(self, item):
        """Handler called when a configuration option of the agent has changed.
        If the option was deleted, this will be called with value set as the
        empty string. Otherwise, value will contain the added or altered string
        corresponding to the option name."""
        logger.info("on_agent_config %s %s", json.dumps(item.key), json.dumps(item.value))

        if item.key == "destination":
            self.handle_destination(item)
        elif item.key == "binary":
            self.handle_binary(item)

        self.run_agent()

        if item.value:
            self.status[item.key] = item.value
        else:
            del self.status[item.key]

    def on_agent_enabled(self, enabled):
        logger.info("on_agent_enabled %s", enabled)

        # Make sure that Promtail is killed
        if self.child:
            child = self.child
            self.child = None
            child.kill()
            self.agent_mgr.status_set("Promtail", "down")

        # Remove all status.
        self.status.clear()

        self.agent_mgr.agent_shutdown_complete_is(True)


def main():
    sdk = eossdk.Sdk("PromtailDaemon")
    _ = PromtailDaemon(sdk)
    sdk.main_loop(sys.argv)


if __name__ == "__main__":
    main()
