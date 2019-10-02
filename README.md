# **eap_proxy-udmpro**
## **Changelog**
*v1.1*
* added option **--update-mongodb** for UDM Pro users to avoid the lost Unifi controller bug
* Created a fixit.py to manually fix the database

*v1.0*
* Initial release

## **Running**
This is a containerized version of eap_proxy based off of kangtastic's linux version of eap_proxy.  Link to his project can be found below.

https://github.com/kangtastic/eap_proxy

This is just a quick description of how to get this up an running.  I might add more details later but for now, the quickest way to get your UDM Pro bypassing the ATT proxy is to run this container via ssh.  You'll need to attach the ONT to port 9(eth8) and the ATT router to port 10 (eth9).  You'll also need a gigabit SFP in port 10 before you can attach your modem.  

You'll need internet on your UDM Pro before you can run this so you can pull the image with the following command.
```
docker pull pbrah/eap_proxy-udmpro:v1.1
```

Below is the docker command to get this running.
```
docker run --privileged --network=host --name=eap_proxy-udmpro --log-driver=json-file --restart unless-stopped -d -ti pbrah/eap_proxy-udmpro:v1.1 --update-mongodb --ping-gateway --ignore-when-wan-up --ignore-start --ignore-logoff --set-mac eth8 eth9
```

You can check the logs of your container to see if it is working, sometimes there might be an error at first but I find after a minute or so it will authenticate properly.
```
docker logs -f eap_proxy-udmpro
```

## **Create your own docker image**
For anyone that wants to create their own docker image, I've provided brief instructions below.

1. copy all files in docker/ and upload them to /root/docker/ on the UDM Pro
2. Build image
```
cd /root/docker/
docker build --network=host -t pbrah/eap_proxy-udmpro:v1.1 .
```

## **Troubleshooting**
If your controller is lost in the UDM Pro menu, you can run fixit.py to ensure there are no duplicates from within the docker container.  If you are impatient you can also restart the unifi controller or reboot your udm to speed up redection.  If you restart the Unifi controller from the command line, sometimes it will spit out some exceptions.  As far as I can tell these are harmless and can be ignored.
```
# docker exec -ti eap_proxy-udmpro fixit.py eth8
'Listing current ethernet_table:'
[{u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth9', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth10', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth0', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth1', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth2', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth3', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth4', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth5', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth6', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth7', u'num_port': 1},
 {u'mac': u'14:ed:bb:xx:xx:x1', u'name': u'eth8', u'num_port': 1}]
''
'Deleting all entries for wan interface:'
''
'eth8'
''
[{u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth9', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth10', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth0', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth1', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth2', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth3', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth4', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth5', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth6', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth7', u'num_port': 1}]
''
'Inserting single entry for wan interface'
''
'eth8'
''
[{u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth9', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth10', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth0', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth1', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth2', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth3', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth4', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth5', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth6', u'num_port': 1},
 {u'mac': u'74:83:c2:xx:xx:xx', u'name': u'eth7', u'num_port': 1},
 {u'mac': u'14:ed:bb:xx:xx:x1', u'name': u'eth8', u'num_port': 1}]
''
# /etc/init.d/S95unifi restart
unifi: Stopping Ubiquiti UniFi Controller unifi
unifi: Starting Ubiquiti UniFi Controller unifi
#

```


# **Kangtastic's eap_proxy original README.md below**

Inspired by 1x_prox as posted here:

[AT&amp;T Residential Gateway Bypass - True bridge mode!](http://www.dslreports.com/forum/r30693618-)

### Forked from [**jaysoffian/eap_proxy**](https://github.com/jaysoffian/eap_proxy).

This fork has been modified for a regular Debian/Ubuntu/whatever system. It should also work with non-Debian-based distributions like RHEL, CentOS, Fedora, etc. just fine.

## Installation
Note: The package, initscript, and [`systemd`](https://en.wikipedia.org/wiki/Systemd) .service file are named `eap-proxy`. Everything else is named with an underscore as `eap_proxy`.

### Debian-based systems
A .deb package is provided. Download the latest [release](https://github.com/kangtastic/eap_proxy/releases/).

Install the package with `sudo dpkg --install eap-proxy_<version>_all.deb`. Configure your system and set the proxy to start at boot (see [**OPTIONS**](#options), [**CONFIGURATION**](#configuration), [**EXAMPLES**](#examples), and [**USAGE**](#usage)).

Reboot.

If everything worked, you will have connectivity. You can verify that `eap_proxy` is doing its job with `grep eap_proxy /var/log/syslog`. If you screwed up, redo your configuration and reboot/restart the daemon with `systemctl restart eap-proxy` as necessary.

### Non-Debian-based systems
##### (also Debian-based systems if you don't want to store your configuration in `/etc/eap_proxy.conf`, or you don't want to use the package)

Assuming you have Python 2 installed, all you really need to download is `eap_proxy.py`. Move it somewhere in your `PATH` and set it executable with something like `sudo install --owner=root --group=root --mode=0755 eap_proxy.py /usr/sbin/eap_proxy`.

You will have to handle starting the proxy with the proper options yourself. A .service file for `systemd` is [provided in the repository](https://github.com/kangtastic/eap_proxy/blob/master/eap-proxy.service) as a model.


## Uninstallation

### Debian-based systems
To keep your configuration, run `sudo dpkg --remove eap-proxy`.

To get rid of everything, run `sudo dpkg --purge eap-proxy`.

### Non-Debian-based systems
Delete the proxy script and any related files from the locations to which you saved them.

## IPv6

For a 6rd tunnel through AT&T, start [here](https://gist.github.com/kangtastic/0e657c1318684785ec9d782de557f9d9).

For native IPv6 through AT&T, start
[here](https://github.com/kangtastic/attnative6).

If you do end up using both `eap_proxy` and either script, remember that your WAN interface may be a VLAN named something like `eth0.0` and not `eth0`.

---

Here, have a manual page.

[SYNOPSIS](#synopsis)
[DESCRIPTION](#description)
[OPTIONS](#options)
[CONFIGURATION](#configuration)
[EXAMPLES](#examples)
[USAGE](#usage)
[FILES](#files)
[ERRATA](#errata)
[AUTHOR](#author)
[SEE ALSO](#see-also)
---
## SYNOPSIS

<pre>
<b>eap_proxy</b> [<b><a href="#h-help">-h</a></b>|<b><a href="#h-help">--help</a></b>] [<b><a href="#pinggateway">--ping-gateway</a></b>] [<b><a href="#ignorewhenwanup">--ignore-when-wan-up</a></b>] [<b><a href="#ignorestart">--ignore-start</a></b>]
          [<b><a href="#ignorelogoff">--ignore-logoff</a></b>] [<b><a href="#--vlan-if_vlan">--vlan</a></b> <b><a href="#--vlan-if_vlan">IF_VLAN</a></b>] [<b><a href="#restartdhcp">--restart-dhcp</a></b>]
          [<b><a href="#setmac">--set-mac</a></b>] [<b><a href="#daemon">--daemon</a></b>] [<b><a href="#pidfile-pidfile">--pidfile</a></b> [<b><a href="#pidfile-pidfile">PIDFILE</a></b>]] [<b><a href="#syslog">--syslog</a></b>]
          [<b><a href="#promiscuous">--promiscuous</a></b>] [<b><a href="#debug">--debug</a></b>] [<b><a href="#debugpackets">--debug-packets</a></b>]
          <b><a href="#if_wan">IF_WAN</a></b> <b><a href="#if_router">IF_ROUTER</a></b>
</pre>

## DESCRIPTION

**`eap_proxy`** proxies 802.1X EAPOL (Extensible Authentication Protocol over LAN) frames between the Ethernet interfaces [**`IF_WAN`**](#if_wan) and [**`IF_ROUTER`**](#if_router).

## OPTIONS

### Required options

##### (all others are optional)

#### `IF_WAN`
Interface to which the WAN uplink is connected.

A VLAN configured to get its IP address automatically via DHCP may also exist on it (e.g. as `eth0.0` on an interface named `eth0`).

See [**CONFIGURATION**](#configuration), [**EXAMPLES**](#examples), and [**interfaces**(5)](https://manpages.debian.org/jessie/ifupdown/interfaces.5.en.html) for more information on how to configure a VLAN interface.

#### `IF_ROUTER`
Interface to which the ISP router is connected.

### Help message
#### −h, −−help
Print a help message.

### Checking whether WAN is up
#### −−ping−gateway
Normally the WAN is considered up if [**`IF_VLAN`**](#--vlan-if_vlan)) has an IP address.

This option additionally requires that there is a default route gateway that responds to a ping.

### Ignoring router packets
#### −−ignore−when−wan−up
Do not proxy any EAPOL traffic from the router when the WAN is up (see [**−−ping−gateway**](#pinggateway)).

#### −−ignore−start
Always ignore **EAPOL−Start** from the router.

A new device on a network with EAP access control is not allowed to use the network for any non-EAP traffic. To start the authentication process, it replies with a **EAP−Response Identity** packet to periodic **EAP−Request Identity** transmissions made by an authenticator. Although not required, devices can also send a **EAPOL−Start** frame on their own to ask any available authenticator to immediately transmit **EAP−Request Identity**.

#### −−ignore−logoff
Always ignore **EAPOL−Logoff** from the router.

Once a device sends **EAPOL−Logoff**, it must authenticate again before using the network for any non-EAP traffic.

### Configuring the VLAN subinterface on [`IF_WAN`](#if_wan)
#### --vlan `IF_VLAN`
VLAN ID or interface name of the VLAN subinterface on [**`IF_WAN`**](#if_wan) (e.g. `0`, `eth0.4`, `vlan0`). The value of **`IF_VLAN`** that is passed to **`eap_proxy`** is a hint to influence what it uses for **`IF_VLAN`** internally. If **--vlan** is specified, both **--vlan** and **`IF_VLAN`** must be specified together. **`IF_VLAN`** may be a VLAN ID number (0 - 4094, inclusive), a network interface name, or `none`.

If **`IF_VLAN`** is specified as a VLAN ID number, the system's VLAN configuration will be checked and the existing VLAN subinterface on [**`IF_WAN`**](#if_wan) with that VLAN ID will be used. For example, given that [**`IF_WAN`**](#if_wan) is `eth0`, and **`IF_VLAN`** was specified as '2', **`eap_proxy`** will change the value of **`IF_VLAN`** that it uses internally to point to the correct VLAN subinterface for your system. The existing VLAN subinterface on `eth0` with VLAN ID 2 could have been named `eth0.2`, `eth0.0002`, `vlan2`, `vlan0002`, or perhaps even something else.

If **`IF_VLAN`** is specified as a network interface name, the system's VLAN configuration will be checked and that network interface will be used if it is an existing VLAN subinterface on [**`IF_WAN`**](#if_wan). For example, given that [**`IF_WAN`**](#if_wan) is `eth0`, **`IF_VLAN`** was specified as `eth0.0`, and `eth0.0` is actually present on the system, **`eap_proxy`** will use `eth0.0` as **`IF_VLAN`**.

If **`IF_VLAN`** is specified as `none`, **`eap_proxy`** will use [**`IF_WAN`**](#if_wan) directly as its internal value for **`IF_VLAN`**.

In the case that **--vlan** is *not* specified at all, **`eap_proxy`** will behave by default as though it were called with **--vlan 0**. For example, given that [**`IF_WAN`**](#if_wan) is `eth0`, **`eap_proxy`** will change the value of **`IF_VLAN`** that it uses internally to point to the VLAN subinterface on `eth0` with VLAN ID 0, whether the system's name for it is `eth0.0`, `eth0.0000`, `vlan0`, `vlan0000`, or something else. However, if no such subinterface exists, this default for **`IF_VLAN`** will be treated as specified but invalid.

Finally, in the error case that **`IF_VLAN`** is specified but invalid, **`eap_proxy`** will behave as though it were called with **--vlan none**, and use [**`IF_WAN`**](#if_wan) directly.

The addition of **--vlan** is to accommodate the fact that although the majority of users with routers set to use VLAN ID 0 appear to be able to successfully use **`eap_proxy`** with no VLAN at all, some users have routers set to use a nonzero VLAN ID and may still need to use a VLAN with a corresponding nonzero VLAN ID. Configurations for older versions of **`eap_proxy`** that assumed the necessity and presence of a VLAN with VLAN ID 0 will continue to be usable with no changes.
#### −−restart−dhcp
Check whether WAN (i.e. [**`IF_VLAN`**](#--vlan-if_vlan)) is up after receiving **EAP−Success** on [**`IF_WAN`**](#if_wan) (see [**−−ping−gateway**](#pinggateway)).
If not, restart the system’s DHCP client on [**`IF_VLAN`**](#--vlan-if_vlan)).

### Setting MAC address
#### −−set−mac
Set [**`IF_WAN`**](#if_wan) and [**`IF_VLAN`**](#--vlan-if_vlan)’s MAC (Ethernet) address to the router’s MAC address.
Matching MAC addresses is probably required, but you may prefer to do it manually instead of having eap_proxy do it for you.

### Daemonization
#### −−daemon
Become a daemon. Implies [**−−syslog**](#syslog).

#### −−pidfile [`PIDFILE`]
Record **`eap_proxy`**’s process identifier to **`PIDFILE`**.
If **−−pidfile** is given, but **`PIDFILE`** is not, **`PIDFILE`** will default to `/var/run/eap_proxy.pid`.

#### −−syslog
Log messages to `syslog` instead of to the standard error stream `stderr`.

### Debugging
#### −−promiscuous
Place the [**`IF_WAN`**](#if_wan) and [**`IF_ROUTER`**](#if_router) interfaces into promiscuous mode instead of multicast mode.

#### −−debug
Enable debug-level logging.

#### −−debug−packets
Print packets in a `hexdump`-like format to assist with debugging.
Implies [**−−debug**](#debug).

## CONFIGURATION

**`eap_proxy`** is installed as a daemon. An initscript is placed at `/etc/init.d/eap−proxy` and a default configuration file at `/etc/eap_proxy.conf`. The configuration file is not used by the proxy itself. Instead, the proxy is configured when it is launched by the initscript, which parses the configuration file to pass on the proper options.

Note that the package and initscript are named `eap−proxy`. Everything else is named with an underscore as **`eap_proxy`**.

### `/etc/eap_proxy.conf`
The default configuration file is a standard text file. Each line contains one option or a comment. Lines beginning with `#` are considered comments and will not be parsed.

The first two options (lines that are not comments) must contain [**`IF_WAN`**](#if_wan) and [**`IF_ROUTER`**](#if_router), the device names of the physical network interfaces connected to the WAN uplink and the ISP router. Most users will only need to edit these two lines in the configuration file.

Users who must use a VLAN subinterface of [**`IF_WAN`**](#if_wan) with a nonzero VLAN ID in order to successfully use **`eap_proxy`** will also need to specify the VLAN ID or interface name by uncommenting and editing the [**−−vlan**](#--vlan-if_vlan) line.

If [**`PIDFILE`**](#pidfile) is specified in addition to [**−−pidfile**](#pidfile), and [**`PIDFILE`**](#pidfile) contains spaces, it must be enclosed in quotes.

If **`eap_proxy`** is run as a daemon via the initscript (or by [`systemd`](https://en.wikipedia.org/wiki/Systemd)’s `systemctl`, which itself runs the initscript), [**−−daemon**](#daemon) is implied and its setting in the configuration file is ignored.

See the [**OPTIONS**](#options) section for more information about options.

### Interfaces and VLAN
[**`IF_WAN`**](#if_wan) and [**`IF_ROUTER`**](#if_router) should be physical network interfaces for most users, but more exotic setups in which they are bridges (hopefully with a single port assigned) are now possible. There may also be a VLAN subinterface on [**`IF_WAN`**](#if_wan) that has VLAN ID 0 to match the behavior of most users' routers, but a VLAN is not a requirement to use **`eap_proxy`**, with the probable exception of users whose routers are configured to use a nonzero VLAN ID.

For [**−−restart−dhcp**](#restartdhcp) to work, at least [**`IF_WAN`**](#if_wan) (and, if present, also [**`IF_VLAN`**](#--vlan-if_vlan)) should not be be managed by `NetworkManager` (which uses an internal DHCP client), but in `/etc/network/interfaces`. [**`IF_WAN`**](#if_wan) (or, if present, [**`IF_VLAN`**](#--vlan-if_vlan), but not both) should be configured to get its IP via DHCP.

For more information on configuring network interfaces, VLANs, and DHCP, see [**EXAMPLES**](#examples) and [**interfaces**(5)](https://manpages.debian.org/jessie/ifupdown/interfaces.5.en.html).

## EXAMPLES
These examples are for a system running a typical Debian-based Linux distribution, and should be followed only with consideration for individual circumstances. If everything is configured perfectly, issuing `sudo systemctl enable eap-proxy` from a command line and restarting the system will fulfill various hopes and dreams.

Firewalling, routing, DNS, IPv6, VPNs, and local DHCP assignments are beyond this document’s scope.

### Assumptions

* The network interface to be used as [**`IF_WAN`**](#if_wan) is named `eth0`,
* the interface to be used as [**`IF_ROUTER`**](#if_router) is named `eth1`,
* a VLAN subinterface named `eth0.0` will be created and used as [**`IF_VLAN`**](#--vlan-if_vlan), and
* the MAC address of the ISP router is `DE:AD:8B:AD:F0:0D`.

### Desired behavior

* We would like to disable `NetworkManager` (see [**Disabling `NetworkManager`**](#disabling-networkmanager) below) on `eth0` and `eth1`,
* change `eth0`'s MAC address to `DE:AD:8B:AD:F0:0D`,
* create a VLAN (see [**Creating VLANs**](#creating-vlans) below) named `eth0.0` on top of `eth0` with VLAN ID 0 that gets its IP via DHCP,
* and bring `eth0`, `eth0.0`, and `eth1` up automatically when the system starts.

### `/etc/network/interfaces`
Place the following lines in `/etc/network/interfaces`.

```
allow−hotplug eth0
iface eth0 inet manual
	hwaddress de:ad:8b:ad:f0:0d

auto eth0.0
iface eth0.0 inet dhcp
	vlan−raw−device eth0

allow−hotplug eth1
iface eth1 inet manual
```
Now that definitions for the network interfaces are in `/etc/network/interfaces`, `NetworkManager` is most likely disabled on them. The MAC address set on `eth0` will be inherited by the VLAN subinterface `eth0.0`.

Some systems will hang for several minutes during boot while `eth0.0` tries and fails to get a DHCP assignment. To fix this, either edit the configuration file for your DHCP client so that it uses a sane value for DHCP timeout, and/or (if using [`systemd`](https://en.wikipedia.org/wiki/Systemd)) edit `/etc/systemd/system/network-online.target.wants` to do the same by adding something like `TimeoutStartSec=10sec` to the `[Service]` section.

### `/etc/eap_proxy.conf`
Edit the first two noncommented lines in [`/etc/eap_proxy.conf`](#etceap_proxyconf), substituting the actual names of your interfaces.

```sh
[ ... ]
# Required options

# IF_WAN
eth0

# IF_ROUTER
eth1
[ ... ]
```
Because the VLAN ID of `eth0.0` is 0, explicitly configuring it as [**`IF_VLAN`**](#--vlan-if_vlan) is not required.

### Disabling `NetworkManager`
The surest way to stop using `NetworkManager` is to uninstall it. It will also will not manage interfaces listed in `/etc/network/interfaces`, if the following is present (which is likely) in `/etc/NetworkManager/NetworkManager.conf`:

```
[main]
plugins=ifupdown,keyfile

[ifupdown]
managed=false
```

### Creating VLANs
VLAN support is provided by the `vlan` package.

VLAN autocreation is handled by the `/etc/network/if−pre−up.d/vlan` script, which normally guesses parameters for the VLAN name type, ID, and raw interface from reading `/etc/network/interfaces`.

At this point, the interface configuration in `/etc/network/interfaces` will probably result in a VLAN subinterface on `eth0` named `eth0.0000`.

**`eap_proxy`** now supports discovering and using this interface as [**`IF_VLAN`**](#--vlan-if_vlan) based on its VLAN ID of 0, but if the automatic creation of a VLAN subinterface named `eth0.0` is desired instead, it is necessary to also edit `/etc/network/interfaces` to supply the aforementioned parameters explicitly:

```bash
case "$IFACE" in
  [ ... ]
  # for eap_proxy: special case to create eth0.0 properly
  eth0.0)
    vconfig set_name_type DEV_PLUS_VID_NO_PAD
    VLANID=0
    IF_VLAN_RAW_DEVICE=eth0
    ;;
  [ ... ]
```

## USAGE

The preferred method of running **`eap_proxy`** is through [`systemd`](https://en.wikipedia.org/wiki/Systemd) by issuing `sudo systemctl start eap-proxy` from the command line.

Issue `sudo systemctl stop eap-proxy` to stop the proxy.

Issue `sudo systemctl enable eap-proxy` to make the proxy run at every boot.

Directly call the proxy from the command line by issuing `eap_proxy [options]`.

Issue `man eap_proxy` to read the manual page.

Setting up routing between [**`IF_WAN`**](#if_wan) (or, if used, [**`IF_VLAN`**](#--vlan-if_vlan)) and another network interface is likely the next step, but will be left as an exercise for the reader.

See the [**CONFIGURATION**](#configuration) and [**EXAMPLES**](#examples) sections for more information.

## FILES
### `/etc/eap_proxy.conf`

Default configuration file. See [**CONFIGURATION**](#configuration) and [**EXAMPLES**](#examples) for more information.

### `/etc/init.d/eap-proxy`

Default initscript. See [**CONFIGURATION**](#configuration) for more information.

### `/usr/sbin/eap_proxy`

Program executable.

## ERRATA

The package and initscript are named **`eap−proxy`**.

Everything else is named with an underscore as **`eap_proxy`**.

An initscript is used instead of a modern [`systemd`](https://en.wikipedia.org/wiki/Systemd) .service file to parse [`/etc/eap_proxy.conf`](#etceap_proxyconf) and pass on the correct options to the proxy. (Backward compatibility, too, for what that’s worth.)

## AUTHOR

[Jay Soffian](https://www.github.com/jaysoffian/) &lt;jaysoffian@gmail.com&gt; (original)

[kangtastic](https://www.github.com/kangtastic/) &lt;kangscinate@gmail.com&gt; (modifications, documentation, and packaging for Debian)

## SEE ALSO

[**interfaces**(5)](https://manpages.debian.org/jessie/ifupdown/interfaces.5.en.html)
