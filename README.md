# Sysrepo Network plugin (generic)

## Introduction

This Sysrepo plugin is responsible for bridging OpenWrt [**UCI**]() (Unified Configuration Interface) and Sysrepo/YANG datastore network interfaces configuration.

## Development Setup

Setup the development environment using the provided [`setup-dev-sysrepo`](https://github.com/sartura/setup-dev-sysrepo) scripts. This will build all the necessary components and initialize a sparse OpenWrt filesystem.

Subsequent rebuilds of the plugin may be done by navigating to the plugin source directory and executing:

```
$ export SYSREPO_DIR=${HOME}/code/sysrepofs
$ cd ${SYSREPO_DIR}/repositories/plugins/network-plugin-openwrt

$ rm -rf ./build && mkdir ./build && cd ./build
$ cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DCMAKE_PREFIX_PATH=${SYSREPO_DIR} \
		-DCMAKE_INSTALL_PREFIX=${SYSREPO_DIR} \
		-DCMAKE_BUILD_TYPE=Debug \
		..
-- The C compiler identification is GNU 9.3.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
[...]
-- Configuring done
-- Generating done
-- Build files have been written to: ${SYSREPO_DIR}/repositories/plugins/network-plugin-openwrt/build

$ make && make install
[...]
[ 75%] Building C object CMakeFiles/sysrepo-plugin-network.dir/src/utils/memory.c.o
[100%] Linking C executable sysrepo-plugin-network
[100%] Built target sysrepo-plugin-network
[100%] Built target sysrepo-plugin-network
Install the project...
-- Install configuration: "Debug"
-- Installing: ${SYSREPO_DIR}/bin/sysrepo-plugin-network
-- Set runtime path of "${SYSREPO_DIR}/bin/sysrepo-plugin-network" to ""

$ cd ..
```

Before using the plugin it is necessary to install relevant YANG modules. For this particular plugin, the following commands need to be invoked:

```
$ cd ${SYSREPO_DIR}/repositories/plugins/network-plugin-openwrt
$ export LD_LIBRARY_PATH="${SYSREPO_DIR}/lib64;${SYSREPO_DIR}/lib"
$ export PATH="${SYSREPO_DIR}/bin:${PATH}"

$ sysrepoctl -i ./yang/ietf-interfaces@2014-05-08.yang
$ sysrepoctl -i ./yang/iana-if-type@2014-05-08.yang
$ sysrepoctl -i ./yang/ietf-ip@2014-06-16.yang
```

## YANG Overview

The `ietf-interfaces` YANG module with the `if` prefix is the main module path populated by this plugin which consists of the following `container` paths:

* `/ietf-interfaces:interfaces` — configurational state data for interfaces

The following items are not configurational i.e. they are `operational` state data:

* `/ietf-interfaces:interfaces-state` — operational data for network interfaces

## Running and Examples

This plugin is installed as the `sysrepo-plugin-network` binary to `${SYSREPO_DIR}/bin/` directory path. Simply invoke this binary, making sure that the environment variables are set correctly:

```
$ sysrepo-plugin-network
[INF]: Applying scheduled changes.
[INF]: File "terastream-interfaces-opto@2017-09-27.yang" was installed.
[INF]: Module "terastream-interfaces-opto" was installed.
[INF]: Scheduled changes applied.
[INF]: Session 7 (user "...") created.
[INF]: plugin: start session to startup datastore
[INF]: Session 8 (user "...") created.
[INF]: plugin: running DS is empty, loading data from UCI
[INF]: There are no subscribers for changes of the module "ietf-interfaces" in running DS.
[INF]: plugin: subscribing to module change
[INF]: plugin: subscribing to get oper items
[INF]: plugin: plugin init done
[...]
```

Output from the plugin is expected; the plugin has loaded UCI configuration at `${SYSREPO_DIR}/etc/config/network` into the `startup` datastore. We can confirm this by invoking the following commands:

```
$ cat ${SYSREPO_DIR}/etc/config/network
config interface 'loopback'
        option is_lan '1'
        option ifname 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config interface 'lan'
        option is_lan '1'
        option type 'bridge'
        option proto 'static'
        option ipaddr '192.168.1.1'
        option netmask '255.255.255.0'
        option ip6assign '64'
        option ifname 'eth1 eth2 eth3 wl0 wl1'
        list ip6class 'local'
        list ip6class '5f414e59'

config interface 'wan'
        option proto 'dhcpv6'
        option ifname 'eth0.1'
        option accept_ra '1'
        option request_pd '3'
        option aftr_v4_local '192.0.0.2'
        option aftr_v4_remote '192.0.0.1'
        option request_na '0'
        option reqopts '21 23 31 56 64 67 88 96 99 123 198 199'

config interface 'lan_iptv'
        option proto 'static'
        option ifname 'eth4'
        option ipaddr '192.168.2.1'
        option netmask '255.255.255.0'
        option ip6assign '64'
        list ip6class 'local'
        list ip6class '5f414e59'
        list ip6class '49505456'
        list ip6class '564f4950'

$ sysrepocfg -X -d startup -f json -m 'ietf-interfaces'
{
  "ietf-interfaces:interfaces": {
    "interface": [
      {
        "name": "loopback",
        "type": "iana-if-type:ethernetCsmacd",
        "ietf-ip:ipv4": {
          "address": [
            {
              "ip": "127.0.0.1",
              "prefix-length": 8
            }
          ]
        }
      },
      {
        "name": "lan",
        "type": "iana-if-type:ethernetCsmacd",
        "ietf-ip:ipv4": {
          "address": [
            {
              "ip": "192.168.1.1",
              "prefix-length": 24
            }
          ]
        }
      },
      {
        "name": "wan",
        "type": "iana-if-type:ethernetCsmacd"
      },
      {
        "name": "lan_iptv",
        "type": "iana-if-type:ethernetCsmacd",
        "ietf-ip:ipv4": {
          "address": [
            {
              "ip": "192.168.2.1",
              "prefix-length": 24
            }
          ]
        }
      }
    ]
  }
}
```

Provided output suggests that the plugin has correctly initialized Sysrepo `startup` datastore with appropriate data transformations. It can be seen that the `interfaces` container has been populated.

Changes to the `running` datastore can be done manually by invoking the following command:

```
$ sysrepocfg -E -d running -f json -m 'ietf-interfaces'
[...interactive...]
{
  "ietf-interfaces:interfaces": {
    "interface": [
      {
        "name": "loopback",
		[...]
      },
      {
        "name": "lan",
        "type": "iana-if-type:ethernetCsmacd",
        "ietf-ip:ipv4": {
          "address": [
            {
              "ip": "192.168.1.1",
              "prefix-length": 24 // => 16
            }
          ]
        }
      },
      {
        "name": "wan",
		[...]
      },
      {
        "name": "lan_iptv",
		[...]
      }
    ]
  }
}
```

Alternatively, instead of changing the entire module data with `-m 'ietf-interfaces'` we can change data on a certain XPath with e.g. `-x '/ietf-interfaces:interfaces'`.

After executing previous command, the following should appear at plugin binary standard output:

```
[...]
[INF]: Processing "ietf-interfaces" "change" event with ID 1 priority 0 (remaining 1 subscribers).
[INF]: plugin: module_name: ietf-interfaces, xpath: /ietf-interfaces:*//*, event: 1, request_id: 1
[DBG]: plugin: uci_path: network.lan.netmask; prev_val: 24; node_val: 16; operation: 1
[INF]: Successful processing of "change" event with ID 1 priority 0 (remaining 0 subscribers).
[INF]: Processing "ietf-interfaces" "done" event with ID 1 priority 0 (remaining 1 subscribers).
[INF]: plugin: module_name: ietf-interfaces, xpath: /ietf-interfaces:*//*, event: 2, request_id: 1
[INF]: Successful processing of "done" event with ID 1 priority 0 (remaining 0 subscribers).
[...]
```

The datastore change operation should be reflected in the `/etc/config/network` UCI file:

```
$ cat ${SYSREPO_DIR}/etc/config/network | grep netmask
        option netmask '255.0.0.0'
        option netmask '255.255.0.0'
        option netmask '255.255.255.0'
```
