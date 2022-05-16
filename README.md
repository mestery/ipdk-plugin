[![ipdk-plugin CI](https://github.com/mestery/ipdk-plugin/actions/workflows/build.yml/badge.svg)](https://github.com/mestery/ipdk-plugin/actions/workflows/build.yml)

# ipdk ebpf docker network plugin

This is a simple Docker CNI which integrates with the [IPDK](https://ipdk.io)
project. Specifically, it works with the
[IPDK P4 eBPF backend](https://github.com/ipdk-io/ipdk/tree/main/build/networking_ebpf).

For more information about IPDK:

* [IPDK Website](https://ipdk.io)
* [IPDK GitHub](https://github.com/ipdk-io/ipdk)

The docker plugin is used to create veth ports between the P4-eBPF switch
namespace and the container's namespace.

# How to use this plugin

Build the plugin:

```
$ go get
$ go build
```

Ensure that your plugin is [discoverable](https://docs.docker.com/engine/extend/plugin_api/#/plugin-discovery)

```
$ sudo cp ipdk.json /etc/docker/plugins/
```

Start the plugin

```
$ sudo ./ipdk-plugin &
```

To run the plugin such that it exposes a GW port into the host where docker is
running, add `-hostports` to the command line:

```
$ sudo ./ipdk-plugin -hostports &
```
        
Note: Enable password less sudo to ensure the plugin will run in the background without prompting.

