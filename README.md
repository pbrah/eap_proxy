# **eap_proxy**

Inspired by 1x_prox as posted here:

[AT&amp;T Residential Gateway Bypass - True bridge mode!](http://www.dslreports.com/forum/r30693618-)

### Forked from [**jaysoffian/eap_proxy**](https://github.com/jaysoffian/eap_proxy).

This fork has been modified for a regular Debian/Ubuntu/whatever system. It also works with non-Debian-based distributions like RHEL, CentOS, Fedora, etc. just fine, for the most part.

## Installation
Note: The package, initscript, and [`systemd`](https://en.wikipedia.org/wiki/Systemd) .service file are named `eap-proxy`. Everything else is named with an underscore as `eap_proxy`.

### Debian-based systems
A .deb package is provided. Download the latest [release](https://github.com/kangtastic/eap_proxy/releases/).

Install the package with `sudo dpkg --install eap-proxy_<version>_all.deb`. Configure your system and set the proxy to start at boot (see [**OPTIONS**](#options), [**CONFIGURATION**](#configuration), [**EXAMPLES**](#examples), and [**USAGE**](#usage)).

Reboot.

If everything worked, you will have connectivity. You can verify that `eap_proxy` is doing its job with `grep eap_proxy /var/log/syslog`. If you screwed up, redo your configuration and reboot/restart the daemon with `systemctl restart eap-proxy` as necessary.

### Non-Debian-based systems

(also Debian-based systems if you don't want to store your configuration in `/etc/eap_proxy.conf`, or you don't want to use the package)

Assuming you have Python 2 installed, all you really need to download is `eap_proxy.py`. Move it somewhere in your path and set it executable with something like `sudo install --owner=root --group=root --mode=0755 eap_proxy.py /usr/sbin/eap_proxy`.

You will have to handle starting the proxy with the proper options yourself. A .service file for `systemd` is [provided in the repository](https://github.com/kangtastic/eap_proxy/blob/master/eap-proxy.service) as a model.

[**--restart-dhcp**](#restartdhcp) will not work. Restart DHCP yourself if needed.


## Uninstallation

### Debian-based systems
To keep your configuration, run `sudo dpkg --remove eap-proxy`.

To get rid of everything, run `sudo dpkg --purge eap-proxy`.

### Non-Debian-based systems
Delete the proxy script and any related files from the locations to which you saved them.

## IPv6

For a 6rd tunnel through AT&T, start [here](https://gist.github.com/kangtastic/0e657c1318684785ec9d782de557f9d9).

If you do end up using both `eap_proxy` and that script, remember that your WAN interface will be a VLAN named something like `eth0.0` and not `eth0`.

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
          [<b><a href="#ignorelogoff">--ignore-logoff</a></b>] [<b><a href="#restartdhcp">--restart-dhcp</a></b>] [<b><a href="#setmac">--set-mac</a></b>] [<b><a href="#daemon">--daemon</a></b>]
          [<b><a href="#pidfile-pidfile">--pidfile</a></b> [<a href="#pidfile-pidfile">PIDFILE</a>]] [<b><a href="#syslog">--syslog</a></b>] [<b><a href="#promiscuous">--promiscuous</a></b>] [<b><a href="#debug">--debug</a></b>]
          [<b><a href="#debugpackets">--debug-packets</a></b>]
          <a href="#if_wan">IF_WAN</a> <a href="#if_router">IF_ROUTER</a>
</pre>

## DESCRIPTION

`eap_proxy` proxies 802.1X EAPOL (Extensible Authentication Protocol over LAN) frames between the Ethernet interfaces [`IF_WAN`](#if_wan) and [`IF_ROUTER`](#if_router).

## OPTIONS

### Required options

#### **`IF_WAN`**
Physical interface to which the AT&amp;T ONT/WAN is connected.

A VLAN named `IF_WAN.0` configured to get its IP address automatically via DHCP must also exist on it (e.g. as `eth0.0` on an interface named `eth0`).

See [**CONFIGURATION**](#configuration), [**EXAMPLES**](#examples), and [**interfaces**(5)](https://manpages.debian.org/jessie/ifupdown/interfaces.5.en.html) for more information on how to configure a VLAN interface.

#### **`IF_ROUTER`**
Physical interface to which the AT&amp;T Residential Gateway is connected.

### Help message
#### **−h**, **−−help**
Print a help message.

### Checking whether WAN is up
#### **−−ping−gateway**
Normally the WAN is considered up if `IF_WAN.0` has an IP address.  
This option additionally requires that there is a default route gateway that responds to a ping.

### Ignoring router packets
#### **−−ignore−when−wan−up**
Do not proxy any EAPOL traffic from the router when the WAN is up (see [**−−ping−gateway**](#pinggateway)).

#### **−−ignore−start**
Always ignore **EAPOL−Start** from the router.  
A new device on a network with EAP access control is not allowed to use the network for any non-EAP traffic. To start the authentication process, it replies with a **EAP−Response Identity** packet to periodic **EAP−Request Identity** transmissions made by an authenticator. Although not required, devices can also send a **EAPOL−Start** frame on their own to ask any available authenticator to immediately transmit **EAP−Request Identity**.

#### **−−ignore−logoff**
Always ignore **EAPOL−Logoff** from the router.  

Once a device sends **EAPOL−Logoff**, it must authenticate again before using the network for any non-EAP traffic.

### Configuring the `IF_WAN.0` VLAN interface
#### **−−restart−dhcp**
Check whether WAN is up after receiving **EAP−Success** on [`IF_WAN`](#if_wan) (see [**−−ping−gateway**](#pinggateway)).  
If not, restart the system’s DHCP client on the `IF_WAN.0` VLAN interface.

#### **−−set−mac**
Set `IF_WAN.0`’s MAC (Ethernet) address to the router’s MAC address.  
Matching MAC addresses is probably required, but you may prefer to do it manually.

### Daemonization
#### **−−daemon**
Become a daemon.  
Implies [**−−syslog**](#syslog).

#### **−−pidfile** [`PIDFILE`]
Record `eap_proxy`’s process identifier to `PIDFILE`.  
If **−−pidfile** is given, but `PIDFILE` is not, `PIDFILE` will default to `/var/run/eap_proxy.pid`.

#### **−−syslog**
Log messages to `syslog` instead of to the standard error stream `stderr`.

### Debugging
#### **−−promiscuous**
Place the [`IF_WAN`](#if_wan) and [`IF_ROUTER`](#if_router) interfaces into promiscuous mode instead of multicast mode.

#### **−−debug**
Enable debug-level logging.

#### **−−debug−packets**
Print packets in a `hexdump`-like format to assist with debugging.  
Implies [**−−debug**](#debug).

## CONFIGURATION

`eap_proxy` is installed as a daemon. An initscript is placed at `/etc/init.d/eap−proxy` and a default configuration file at `/etc/eap_proxy.conf`. The configuration file is not used by the proxy itself. Instead, the proxy is configured when it is launched by the initscript, which parses the configuration file to pass on the proper options.

Note that the package and initscript are named `eap−proxy`. Everything else is named with an underscore as `eap_proxy`.

### `/etc/eap_proxy.conf`
The default configuration file is a standard text file. Each line contains one option or a comment. Lines beginning with `#` are considered comments and will not be parsed.

The first two options (lines that are not comments) must contain [`IF_WAN`](#if_wan) and [`IF_ROUTER`](#if_router), the device names of the physical network interfaces connected to the AT&amp;T ONT and the AT&amp;T Residential Gateway. Most users will only need to edit these two lines in the configuration file.

If `PIDFILE` is specified in addition to [**−−pidfile**](#pidfile), and `PIDFILE` contains spaces, it must be enclosed in quotes.

If `eap_proxy` is run as a daemon via the initscript (or by [`systemd`](https://en.wikipedia.org/wiki/Systemd)’s `systemctl`, which itself runs the initscript), [**−−daemon**](#daemon) is implied and its setting in the configuration file is ignored.

See the [**OPTIONS**](#options) section for more information about options.

### Interfaces and VLAN
Both [`IF_WAN`](#if_wan) and [`IF_ROUTER`](#if_router) must be physical network interfaces. There must also be a VLAN interface named `IF_WAN.0` on top of [`IF_WAN`](#if_wan) that has VLAN ID 0.

For [**−−restart−dhcp**](#restartdhcp) to work, at least [`IF_WAN`](#if_wan) and `IF_WAN.0` should be managed in `/etc/network/interfaces` instead of by `NetworkManager`, and `IF_WAN.0` should be configured to get its IP via DHCP.

For more information on configuring network interfaces, VLANs, and DHCP, see [**EXAMPLES**](#examples) and [**interfaces**(5)](https://manpages.debian.org/jessie/ifupdown/interfaces.5.en.html).

## EXAMPLES
These examples are for a system running a typical Debian-based Linux distribution, and should be followed only with consideration for individual circumstances. If everything is configured perfectly, issuing `sudo systemctl enable eap-proxy` from a command line and restarting the system will fulfill various hopes and dreams.

Firewalling, routing, DNS, IPv6, VPNs, and local DHCP assignments are beyond this document’s scope.

### Assumptions

* The network interface to be used as [`IF_WAN`](#if_wan) is named `eth0` (implying that `IF_WAN.0` would be named `eth0.0`),
* the interface to be used as [`IF_ROUTER`](#if_router) is named `eth1`, and
* the MAC address of the AT&amp;T Residential Gateway is `DE:AD:8B:AD:F0:0D`.

### Desired behavior

* We would like to disable `NetworkManager` (see [Disabling `NetworkManager`](#disabling-networkmanager) below) on `eth0` and `eth1`,
* change `eth0`'s MAC address to `DE:AD:8B:AD:F0:0D`,
* create a VLAN (see [Creating VLANs](#creating-vlans) below) named `eth0.0` on top of `eth0` with VLAN ID 0 that gets its IP via DHCP,
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

### Disabling `NetworkManager`
The surest way to stop using `NetworkManager` is to uninstall it. It will also will not manage interfaces listed in `/etc/network/interfaces`, if the following is present (which is likely) in `/etc/NetworkManager/NetworkManager.conf`:

```
[main]
plugins=ifupdown,keyfile

[ifupdown]
managed=false
```

### Creating VLANs
VLAN support is provided by the `vlan` package. VLAN autocreation is handled by the `/etc/network/if−pre−up.d/vlan` script, which will almost certainly need to be edited to add a special case for `IF_WAN.0`, explicitly specifying the parameters that it normally guesses from reading `/etc/network/interfaces` for the VLAN name type, ID, and underlying interface:
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

The preferred method of running `eap_proxy` is through [`systemd`](https://en.wikipedia.org/wiki/Systemd) by issuing `sudo systemctl start eap-proxy` from the command line.

Issue `sudo systemctl stop eap-proxy` to stop the proxy.

Issue `sudo systemctl enable eap-proxy` to make the proxy run at every boot.

Directly call the proxy from the command line by issuing `eap_proxy [options]`.

Issue `man eap_proxy` to read the manual page.

Setting up routing between `IF_WAN.0` and another network interface is likely the next step, but will be left as an exercise for the reader.

See the [**CONFIGURATION**](#configuration) and [**EXAMPLES**](#examples) sections for more information.

## FILES
### `/etc/eap_proxy.conf`

Default configuration file. See [**CONFIGURATION**](#configuration) and [**EXAMPLES**](#examples) for more information.

### `/etc/init.d/eap-proxy`

Default initscript. See [**CONFIGURATION**](#configuration) for more information.

## ERRATA

The package and initscript are named `eap−proxy`.

Everything else is named with an underscore as `eap_proxy`.

An initscript is used instead of a modern [`systemd`](https://en.wikipedia.org/wiki/Systemd) .service file to parse [`/etc/eap_proxy.conf`](#etceap_proxyconf) and pass on the correct options to the proxy. (Backward compatibility, too, for what that’s worth.)

## AUTHOR

[Jay Soffian](https://www.github.com/jaysoffian/) &lt;jaysoffian@gmail.com&gt; (original)

[kangtastic](https://www.github.com/kangtastic/) &lt;kangscinate@gmail.com&gt; (modifications, documentation, and packaging for Debian)

## SEE ALSO

[**interfaces**(5)](https://manpages.debian.org/jessie/ifupdown/interfaces.5.en.html)
