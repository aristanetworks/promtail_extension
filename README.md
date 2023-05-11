# Promtail Extension for EOS

## LICENSE

Licensed under the [BSD 3-clause license](LICENSE.md)

## Contents
- [`Introduction`](#introduction)
- [`Building from Source`](#building-from-source)
- [`Description`](#description)

---

## Introduction


Promtail Extension is an EOS extension which wraps the upstream released binary for Promtail in an
EOS Extension, including a CLI.

Once installed and running, this extension adds CLI to EOS, enabling promtail to be configured
as below.

```
promtail
   destination https://my-loki-server/loki/api/v1/push
   no disabled
```

Currently, this would result in a promtail configuration like this:

```
clients:
- https://loki-gateway.dev.corp.arista.io/loki/api/v1/push
positions:
  filename: /tmp/positions.yaml
scrape_configs:
- job_name: system
  pipeline_stages: []
  static_configs:
  - labels:
      __path__: /var/log/agents-latest/*
      host: dmb224
      job: agent_logs
    targets:
    - localhost
server:
  grpc_listen_port: 0
  http_listen_port: 0
```

## Building from Source

Promtail Extension can be built from source, using the supplied `Makefile`.

To build, ensure that sub-modules are cloned and run `make` within
repository root:

```console
git clone --recursive https://github.com/aristanetworks/promtail_extension.git
cd promtail_extension
make
```

The result is a versioned .swix file, in the same directory as the `Makefile`.

## Description

Applications on EOS are implemented as EOSSDK extensions. EOSSDK is a powerful
API which enables third parties to integrate with Arista's OS. The EOS software
can co-exist with the MOS software but uses an orthogonal set of interfaces.
Detailed documentation for EOSSDK and examples can be found on github:
https://github.com/aristanetworks/EosSdk

The software which implements the Promtail Extension is located in the
`src/eos` directory.

The integration with EOS has 3 main components:


| File                  | Description                                                                                                                                                                                                       |
|-----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Promtail.yaml`     | A YAML file which describes the CLI commands and daemon.                                                                                                                                                          |
| `PromtailCli.py`    | A Python file which is loaded by the CLI processor in EOS. It implements classes which are called by EOS when CLI commands are entered. This may read from the status store, and write to the config store.       |
| `PromtailDaemon.py` | A Python file which implements a daemon which responds to configuration updates, and publishes status. In the case of `promtail`, it responds to `no disable` commands by starting the promtail binary. |
