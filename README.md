# ipdk docker network plugin

This is simple standalone Docker Plugin implementation to demonstrate Kata
Containers v1 with [IPDK](https://ipdk.io). NOTE: v1 of Kata Containers has
been deprecated. The reason we're using this version is that Docker does not
support the V2 shim API, meaning Kata Containers v2 does not work with Docker
(or podman, for that matter). See [here](https://github.com/kata-containers/kata-containers/issues/722)
for more details.

For more details about Kata Containers v1:
* [GitHub](https://github.com/kata-containers/kata-containers/tree/1.x-eol)

For more information about IPDL:
* [IPDK Website](https://ipdk.io)
* [IPDK GitHub](https://github.com/ipdk-io/ipdk)

The docker plugin is used to create the IPDK vhost-user interface inside the IPDK
docker container, which is attached to the kata container.

# How to use this plugin

0. Build this plugin. 

```
$ go get
$ go build
```

1. Ensure that your plugin is discoverable https://docs.docker.com/engine/extend/plugin_api/#/plugin-discovery

```
$ sudo cp ipdk.json /etc/docker/plugins/
```

2. Start the plugin

```
$ sudo ./ipdk-docker-network-plugin&
```
        
Note: Enable password less sudo to ensure the plugin will run in the background without prompting.

3. Try IPDK with Kata Containers v1:

Follow the instructions in the PoC repository to try this out in a Virtualbox
environment.
