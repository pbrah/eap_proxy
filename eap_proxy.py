#!/usr/bin/env python
"""
Inspired by 1x_prox as posted here:

    http://www.dslreports.com/forum/r30693618-

    AT&T Residential Gateway Bypass - True bridge mode!

usage: eap_proxy [-h] [--ping-gateway] [--ignore-when-wan-up] [--ignore-start]
                 [--ignore-logoff] [--vlan IF_VLAN] [--restart-dhcp]
                 [--set-mac] [--daemon] [--pidfile [PIDFILE]] [--syslog]
                 [--promiscuous] [--debug] [--debug-packets]
                 IF_WAN IF_ROUTER

positional arguments:
  IF_WAN                interface connected to the WAN uplink
  IF_ROUTER             interface connected to the ISP router

optional arguments:
  -h, --help            show this help message and exit

 checking whether WAN is up:
  --ping-gateway        normally the WAN is considered up if IF_VLAN has an IP
                        address; this option additionally requires that there
                        is a default route gateway that responds to a ping

 ignoring router packets:
  --ignore-when-wan-up  ignore router packets when WAN is up (see --ping-
                        gateway)
  --ignore-start        always ignore EAPOL-Start from router
  --ignore-logoff       always ignore EAPOL-Logoff from router

 configuring VLAN subinterface on IF_WAN:
  --vlan IF_VLAN        VLAN ID or interface name of the VLAN subinterface on
                        IF_WAN (e.g. '0' to use IF_WAN.0, 'vlan0' to use
                        vlan0), or 'none' to use IF_WAN directly; if --vlan
                        not specified, treated as though it were with IF_VLAN
                        of 0
  --restart-dhcp        check whether WAN is up after receiving EAP-Success on
                        IF_WAN (see --ping-gateway); if not, restart system's
                        DHCP client on IF_VLAN

 setting MAC address:
  --set-mac             set IF_WAN and IF_VLAN's MAC (ether) address to
                        router's MAC address

 daemonization:
  --daemon              become a daemon; implies --syslog
  --pidfile [PIDFILE]   record pid to PIDFILE; default: /var/run/eap_proxy.pid
  --syslog              log to syslog instead of stderr

 debugging:
  --promiscuous         place interfaces into promiscuous mode instead of
                        multicast
  --debug               enable debug-level logging
  --debug-packets       print packets in hex format to assist with debugging;
                        implies --debug
"""
# pylint:disable=invalid-name,missing-docstring
import argparse
import array
import atexit
import ctypes
import ctypes.util
import logging
import logging.handlers
import os
import random
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import traceback
from collections import namedtuple
from distutils.spawn import find_executable
from fcntl import ioctl
from functools import partial

### Constants

EAP_MULTICAST_ADDR = (0x01, 0x80, 0xc2, 0x00, 0x00, 0x03)
ETH_P_PAE = 0x888e  # IEEE 802.1X (Port Access Entity)
IFF_PROMISC = 0x100
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_MULTICAST = 0
PACKET_MR_PROMISC = 1
SIOCGIFADDR = 0x8915
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SOL_PACKET = 263

### Sockets / Network Interfaces

class struct_packet_mreq(ctypes.Structure):
    # pylint:disable=too-few-public-methods
    _fields_ = (
        ("mr_ifindex", ctypes.c_int),
        ("mr_type", ctypes.c_ushort),
        ("mr_alen", ctypes.c_ushort),
        ("mr_address", ctypes.c_ubyte * 8))


if_nametoindex = ctypes.CDLL(ctypes.util.find_library('c')).if_nametoindex


def addsockaddr(sock, address):
    """Configure physical-layer multicasting or promiscuous mode for `sock`.
       If `addr` is None, promiscuous mode is configured. Otherwise `addr`
       should be a tuple of up to 8 bytes to configure that multicast address.
    """
    # pylint:disable=attribute-defined-outside-init
    mreq = struct_packet_mreq()
    mreq.mr_ifindex = if_nametoindex(getifname(sock))
    if address is None:
        mreq.mr_type = PACKET_MR_PROMISC
    else:
        mreq.mr_type = PACKET_MR_MULTICAST
        mreq.mr_alen = len(address)
        mreq.mr_address = address
    sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)


def rawsocket(ifname, poll=None, promisc=False):
    """Return raw socket listening for 802.1X packets on `ifname` interface.
       The socket is configured for multicast mode on EAP_MULTICAST_ADDR.
       Specify `promisc` to enable promiscuous mode instead.
       Provide `poll` object to register socket to it POLLIN events.
    """
    s = socket.socket(
        socket.PF_PACKET,  # pylint:disable=no-member
        socket.SOCK_RAW,
        socket.htons(ETH_P_PAE))
    s.bind((ifname, 0))
    addsockaddr(s, None if promisc else EAP_MULTICAST_ADDR)
    if poll is not None:
        poll.register(s, select.POLLIN)  # pylint:disable=no-member
    return s


def getifname(sock):
    """Return interface name of `sock`"""
    return sock.getsockname()[0]


def getifaddr(ifname):
    """Return IP addr of `ifname` interface in 1.2.3.4 notation
       or None if no IP is assigned or other IOError occurs.
    """
    # pylint:disable=attribute-defined-outside-init
    ifreq = "%-32s" % (ifname + "\0")
    try:
        result = ioctl(socket.socket(), SIOCGIFADDR, ifreq)
    except IOError:
        return None
    return socket.inet_ntoa(result[20:24])


def getifhwaddr(ifname):
    """Return MAC address for `ifname` as a packed string."""
    with open("/sys/class/net/%s/address" % ifname) as f:
        s = f.readline()
    octets = s.split(':')
    return ''.join(chr(int(x, 16)) for x in octets)


def getdefaultgatewayaddr():
    """Return IP of default route gateway (next hop) in 1.2.3.4 notation
       or None if there is not default route.
    """
    search = re.compile(r"^\S+\s+00000000\s+([0-9a-fA-F]{8})").search
    with open("/proc/net/route") as f:
        for line in f:
            m = search(line)
            if m:
                hexaddr = m.group(1)
                octets = (hexaddr[i:i + 2] for i in xrange(0, 7, 2))
                ipaddr = '.'.join(str(int(octet, 16)) for octet in octets)
                return ipaddr

### Ping

def ipchecksum(packet):
    """Return IP checksum of `packet`"""
    # c.f. https://tools.ietf.org/html/rfc1071
    arr = array.array('H', packet + '\0' if len(packet) % 2 else packet)
    chksum = sum(arr)
    chksum = (chksum >> 16) + (chksum & 0xffff)  # add high and low 16 bits
    chksum += chksum >> 16  # add carry
    chksum = ~chksum & 0xffff  # invert and truncate
    return socket.htons(chksum)  # per RFC 1071


def pingaddr(ipaddr, data='', timeout=1.0, strict=False):
    """Return True if `ipaddr` replies to an ICMP ECHO request within
       `timeout` seconds else False. Provide optional `data` to include in
       the request. Any reply from `ipaddr` will suffice. Use `strict` to
       accept only a reply matching the request.
    """
    # pylint:disable=too-many-locals
    # construct packet
    if len(data) > 2000:
        raise ValueError("data too large")
    icmp_struct = struct.Struct("!BBHHH")
    echoid = os.getpid() & 0xffff
    seqnum = random.randint(0, 0xffff)
    chksum = ipchecksum(icmp_struct.pack(8, 0, 0, echoid, seqnum) + data)
    packet = icmp_struct.pack(8, 0, chksum, echoid, seqnum) + data
    # send it and check reply
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
    sock.sendto(packet, (ipaddr, 1))
    t0 = time.time()
    while time.time() - t0 < timeout:
        ready, __, __ = select.select([sock], (), (), timeout)
        if not ready:
            return False
        packet, peer = sock.recvfrom(2048)
        if peer[0] != ipaddr:
            continue
        if not strict:
            return True
        # verify it's a reply to the packet we just sent
        packet = packet[20:]  # strip IP header
        fields = icmp_struct.unpack(packet[:8])
        theirs = fields[-2:] + (packet[8:],)
        if theirs == (echoid, seqnum, data):
            return True
    return False

### Helpers

def strbuf(buf):
    """Return `buf` formatted as a hex dump (like tcpdump -xx)."""
    out = []
    for i in xrange(0, len(buf), 16):
        octets = (ord(x) for x in buf[i:i + 16])
        pairs = []
        for octet in octets:
            pad = '' if len(pairs) % 2 else ' '
            pairs.append("%s%02x" % (pad, octet))
        out.append("0x%04x: %s" % (i, '' .join(pairs)))
    return '\n'.join(out)


def strmac(mac):
    """Return packed string `mac` formatted like aa:bb:cc:dd:ee:ff."""
    return ':'.join("%02x" % ord(b) for b in mac[:6])


def strexc():
    """Return current exception formatted as a single line suitable
       for logging.
    """
    try:
        exc_type, exc_value, tb = sys.exc_info()
        if exc_type is None:
            return ''
        # find last frame in this script
        lineno, func = 0, ''
        for frame in traceback.extract_tb(tb):
            if frame[0] != __file__:
                break
            lineno, func = frame[1:3]
        return "exception in %s line %s (%s: %s)" % (
            func, lineno, exc_type.__name__, exc_value)
    finally:
        del tb


def pidexist(pid):
    """Return whether `pid` is the PID of a running process."""
    try:
        os.kill(int(pid), 0)
    except OSError as ex:
        return ex.errno != 3
    return True


def killpidfile(pidfile, signum):
    """Send `signum` to PID recorded in `pidfile`.
       Return PID if successful, else return None.
    """
    try:
        with open(pidfile) as f:
            pid = int(f.readline())
        os.kill(pid, signum)
        return pid
    except (EnvironmentError, ValueError):
        pass


def checkpidfile(pidfile):
    """Check whether a process is running with the PID in `pidfile`.
       Return PID if successful, else return None.
    """
    return killpidfile(pidfile, 0)


def safe_unlink(path):
    """rm -f `path`"""
    try:
        os.unlink(path)
    except EnvironmentError:
        pass


def writepidfile(pidfile):
    """Write current pid to `pidfile`."""
    with open(pidfile, 'w') as f:
        f.write("%s\n" % os.getpid())

    # NOTE: called on normal Python exit, but not on SIGTERM.
    @atexit.register
    def removepidfile(_remove=os.remove):  # pylint:disable=unused-variable
        try:
            _remove(pidfile)
        except Exception:  # pylint:disable=broad-except
            pass


def daemonize():
    """Convert process into a daemon."""
    if os.fork():
        sys.exit(0)
    os.chdir("/")
    os.setsid()
    os.umask(0)
    if os.fork():
        sys.exit(0)
    sys.stdout.flush()
    sys.stderr.flush()
    nullin = open('/dev/null', 'r')
    nullout = open('/dev/null', 'a+')
    nullerr = open('/dev/null', 'a+', 0)
    os.dup2(nullin.fileno(), sys.stdin.fileno())
    os.dup2(nullout.fileno(), sys.stdout.fileno())
    os.dup2(nullerr.fileno(), sys.stderr.fileno())


def make_logger(use_syslog=False, debug=False):
    """Return new logging.Logger object."""
    if use_syslog:
        formatter = logging.Formatter("eap_proxy[%(process)d]: %(message)s")
        formatter.formatException = lambda *__: ''  # no stack trace to syslog
        SysLogHandler = logging.handlers.SysLogHandler
        handler = SysLogHandler("/dev/log", facility=SysLogHandler.LOG_LOCAL7)
        handler.setFormatter(formatter)
    else:
        formatter = logging.Formatter("[%(asctime)s]: %(message)s")
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)

    logger = logging.getLogger("eap_proxy")
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


def network_interface(ifname, sysifdir="/sys/class/net/"):
    """A `type` for ArgumentParser.add_argument(). Return
       `ifname` if `ifname` is the name of a network
       interface, else raise argparse.ArgumentTypeError.
    """
    # only physical and virtual devices are in /sys/class/net/, no aliases
    ifs = [name for name in os.listdir(sysifdir)]
    if ifname not in ifs:
        err = (("'%s' isn't a network interface; "
                "you probably meant one of: %s") %
               (ifname, " ".join(sorted(ifs))))
        raise argparse.ArgumentTypeError(err)
    return ifname


    # NOTE: If RG is set to use VLAN ID 0, no VLAN is needed to bypass. If RG
    # is set to use a nonzero VLAN ID, then a VLAN subinterface with that VLAN
    # ID must be created on IF_WAN.
    #
    # Debian autoconfigures VLANs using /etc/network/if-pre-up.d/vlan, which
    # pads VLAN IDs in the resulting interface name by default ("auto eth0.0"
    # results in a VLAN named eth0.0000, for example) when deriving raw device
    # name, VLAN ID, and name padding arguments for vconfig from things named
    # <thing>.<digits> it finds in /etc/network/interfaces.
    #
    # If this is not desired, a workaround is to edit vlan and add a special
    # case exactly matching the desired VLAN interface name, as in the example
    # below for an interface named eth0.0.
    #
    # case "$IFACE" in
    # [ ... ]
    #   # for eap_proxy: special case to create eth0.0 properly
    #   eth0.0)
    #      vconfig set_name_type DEV_PLUS_VID_NO_PAD
    #      VLANID=0
    #      IF_VLAN_RAW_DEVICE=eth0
    #   ;;
    # [ ... ]
def set_vlan(args, vlanconfig="/proc/net/vlan/config"):
    """Validate and set the name of the VLAN interface from
       the command-line arguments provided at runtime."""
    if args.vlan == "none":
        args.vlan = args.if_wan
        return
    elif args.vlan.isdigit():
        args.vlan = str(int(args.vlan))
    # Parse the kernel VLAN configuration in /proc to check if IF_VLAN is
    # either the VLAN ID or the interface name of an existing VLAN on IF_WAN.
    # If the former, set IF_VLAN to the interface name of that VLAN.
    # If parsing failed or IF_VLAN was something else, set IF_VLAN to IF_WAN
    # and raise EnvironmentError.
    search = re.compile(r"(\S+)\s*\|\s+(\d+)\s+\|\s+%s" %
                        args.if_wan).search
    try:
        with open(vlanconfig) as f:
            for line in f:
                match = search(line)
                if match:
                    if args.vlan == match.group(2):
                        args.vlan = match.group(1)
                        return
                    elif args.vlan == match.group(1):
                        return
    # pylint:disable=broad-except
    except Exception:
        pass
    err = ("--vlan: '%s' is not the name or the VLAN ID number of an "
           "existing VLAN subinterface of %s; falling back to use %s as "
           "IF_VLAN" % (args.vlan, args.if_wan, args.if_wan))
    args.vlan = args.if_wan
    raise EnvironmentError(err)


### Linux

class LinuxOS(object):
    def __init__(self, log):
        self.log = log

    def run(self, shellcmd):
        try:
            # subprocess.check_output(args) ignores stderr, but for some reason
            # check_output(args, stderr=subprocess.STDOUT) isn't working, at
            # least when running as a daemon, with the following syslog output:
            # eap_proxy[nnn]: exception in run line nnn (AttributeError: 'list'
            #     object has no attribute 'rfind'); restarting in 10 seconds
            # Workaround by passing the command + arguments as one string and
            # shell=True to check_output(). Also, validate IF_WAN, IF_ROUTER and
            # IF_VLAN when parsing script arguments to prevent shell injection.
            return 0, subprocess.check_output(shellcmd,
                                              stderr=subprocess.STDOUT,
                                              universal_newlines=True,
                                              shell=True)
        except subprocess.CalledProcessError as ex:
            self.log.warn("%s exited %d", shellcmd, ex.returncode)
            return ex.returncode, ex.output

    def stop_dhcp_client(self, allinstances, iface):
        """Stop running instances of DHCP clients on the `iface` interface.
           Return the number of instances that were stopped."""
        ret = 0
        # Try graceful shutdown at first, then send SIGTERM, then send SIGKILL.
        for client, instances in enumerate(allinstances):
            for instancenum, instance in enumerate(instances):
                ret += 1
                # instance[0], instance[1], instance[2] are, respectively:
                # PID as string, executable path, list of its cmdline arguments
                if client == 2:  # udhcpc: send SIGUSR2
                    self.log.debug("stop_dhcp_client: sending SIGUSR2 to %s",
                                   instance[0])
                    os.kill(int(instance[0]), 12)
                else:
                    cmd = instance[1]
                    if client == 0: # dhclient: rerun w/ same args prepending -r
                        cmd += " -r " + " ".join(instance[2])
                    elif client == 1: # pump: rerun with -i `iface` -r
                        cmd += " -i " + iface + " -r"
                    elif client == 3: # dhcpcd: rerun with -k `iface`
                        cmd += " -k " + iface
                    cmd = cmd.strip() # for some reason there's a trailing space
                    self.log.debug("stop_dhcp_client: call \"%s\"", cmd)
                    self.run(cmd)
                time.sleep(5) # Give the client 5 seconds to cleanup and quit.
                # pump is a daemon that always runs as a single instance, but
                # kill all other instances of any client that are still left
                if client == 1 and instancenum == 0:
                    continue
                if pidexist(instance[0]):
                    os.kill(instance[0], 15)
                    time.sleep(10) # Wait a generous 10s before sending SIGKILL
                if pidexist(instance[0]):
                    os.kill(instance[0], 9)
        return ret

    def start_dhcp_client(self, allinstances):
        """Restart an instance of a previously killed DHCP client
           on the `iface` interface. It is started with the same
           command-line arguments with which it ran originally."""
        # Assume that first instance of the first DHCP client we tried to
        # stop is the one we want to restart.
        for instances in allinstances:
            for instance in instances:
                cmd = " ".join([instance[1]] + instance[2]).strip()
                self.log.debug("start_dhcp_client: call \"%s\"", cmd)
                self.run(cmd)
                return

    def restart_dhcp_client(self, iface):
        """Restart the system's DHCP client on the `iface` interface."""
        def dhcp_client_instances(client):
            # Find PID and cmdline of running DHCP client(s) on `iface`.
            # Returns a list containg metadata for each running instance:
            # [['PID1', '$0', ['$1', '$2', ... ]], ['PID2', '$0', [ $1, ... ]]]
            ret = []
            pids = [pid for pid in os.listdir("/proc/") if pid.isdigit()]
            search = re.compile(r"^(.*\/)?%s\x00" % client).search
            spaces = re.compile(r"\s").search
            for pid in pids:
                clpath = "/proc/%s/cmdline" % pid
                if os.path.isfile(clpath) and os.access(clpath, os.R_OK):
                    try:
                        with open(clpath) as f:
                            # `cl` is a str with null-separated fields for
                            # (the path to) an executable and its arguments.
                            # Any field may contain spaces. We need to put
                            # quotes around the contents of space-containing
                            # fields if we want to pass them in a str to
                            # the shell-invoking self.run() later.
                            cl = f.readline()
                            if search(cl) and iface in cl:
                                cmd = cl.split("\0")[0]
                                if spaces(cmd):
                                    cmd = "'" + cmd + "'"
                                args = [arg if not spaces(arg)
                                        else "\"" + arg + "\""
                                        for arg in cl.split("\0")[1:]]
                                ret.append([pid, cmd, args])
                    except Exception:  #pylint:disable=broad-except
                        pass
            return ret

        # Collect a list of lists returned by dhcp_client_instances().
        allinstances = []
        for client in ("dhclient", "pump", "udhcpc", "dhcpcd"):
            allinstances.append(dhcp_client_instances(client))

        if self.stop_dhcp_client(allinstances, iface):
            self.start_dhcp_client(allinstances)
        else:
            self.log.warn("%s: did nothing, no DHCP client was running", iface)

    def setmac(self, if_vlan, if_wan, mac):
        """Set `if_vlan` and `if_wan` interfaces' MAC to `mac`, which may
           be either a packed string or in "aa:bb:cc:dd:ee:ff" format."""
        if len(mac) == 6:
            mac = strmac(mac)
        # just order the commands so it doesn't matter if if_vlan == if_wan
        util = find_executable("ip"), find_executable("ifconfig")
        if util[0] and os.access(util[0], os.X_OK):
            self.run("%s link set dev %s down" % (util[0], if_vlan))
            self.run("%s link set dev %s down" % (util[0], if_wan))
            self.run("%s link set dev %s address %s" % (util[0], if_wan, mac))
            self.run("%s link set dev %s address %s" % (util[0], if_vlan, mac))
            self.run("%s link set dev %s up" % (util[0], if_wan))
            self.run("%s link set dev %s up" % (util[0], if_vlan))
        elif util[1] and os.access(util[1], os.X_OK):
            self.run("%s %s down" % (util[1], if_vlan))
            self.run("%s %s down" % (util[1], if_wan))
            self.run("%s %s hw ether %s" % (util[1], if_wan, mac))
            self.run("%s %s hw ether %s" % (util[1], if_vlan, mac))
            self.run("%s %s up" % (util[1], if_wan))
            self.run("%s %s up" % (util[1], if_vlan))

    @staticmethod
    def getmac(ifname):
        """Return MAC address for `ifname` as a packed string."""
        return getifhwaddr(ifname)

### EAP frame/packet decoding
# c.f. https://github.com/the-tcpdump-group/tcpdump/blob/master/print-eap.c

class EAPFrame(namedtuple("EAPFrame", "dst src version type length packet")):
    __slots__ = ()
    _struct = struct.Struct("!6s6sHBBH")  # includes ethernet header
    TYPE_PACKET = 0
    TYPE_START = 1
    TYPE_LOGOFF = 2
    TYPE_KEY = 3
    TYPE_ENCAP_ASF_ALERT = 4
    _types = {
        TYPE_PACKET: "EAP packet",
        TYPE_START: "EAPOL start",
        TYPE_LOGOFF: "EAPOL logoff",
        TYPE_KEY: "EAPOL key",
        TYPE_ENCAP_ASF_ALERT: "Encapsulated ASF alert"
    }

    @classmethod
    def from_buf(cls, buf):
        unpack, size = cls._struct.unpack, cls._struct.size
        dst, src, etype, ver, ptype, length = unpack(buf[:size])
        if etype != ETH_P_PAE:
            raise ValueError("invalid ethernet type: 0x%04x" % etype)
        if ptype == cls.TYPE_PACKET:
            packet = EAPPacket.from_buf(buf[size:size + length])
        else:
            packet = None
        return cls(dst, src, ver, ptype, length, packet)

    @property
    def type_name(self):
        return self._types.get(self.type, "???")

    @property
    def is_start(self):
        return self.type == self.TYPE_START

    @property
    def is_logoff(self):
        return self.type == self.TYPE_LOGOFF

    @property
    def is_success(self):
        return self.packet and self.packet.is_success

    def __str__(self):
        return "%s > %s, %s (%d) v%d, len %d%s" % (
            strmac(self.src), strmac(self.dst),
            self.type_name, self.type, self.version, self.length,
            ", " + str(self.packet) if self.packet else '')


class EAPPacket(namedtuple("EAPPacket", "code id length data")):
    __slots__ = ()
    _struct = struct.Struct("!BBH")
    REQUEST, RESPONSE, SUCCESS, FAILURE = 1, 2, 3, 4
    _codes = {
        REQUEST: "Request",
        RESPONSE: "Response",
        SUCCESS: "Success",
        FAILURE: "Failure"
    }

    @classmethod
    def from_buf(cls, buf):
        unpack, size = cls._struct.unpack, cls._struct.size
        code, id_, length = unpack(buf[:size])
        data = buf[size:size + length - 4]
        return cls(code, id_, length, data)

    @property
    def code_name(self):
        return self._codes.get(self.code, "???")

    @property
    def is_success(self):
        return self.code == self.SUCCESS

    def __str__(self):
        return "%s (%d) id %d, len %d [%d]" % (
            self.code_name, self.code, self.id, self.length, len(self.data))

### EAP Proxy

class EAPProxy(object):

    def __init__(self, args, log):
        self.args = args
        self.os = LinuxOS(log)
        self.log = log

    def proxy_forever(self):
        log = self.log
        while True:
            try:
                log.info("proxy_loop starting")
                self.proxy_loop()
            except KeyboardInterrupt:
                return
            except Exception as ex:  # pylint:disable=broad-except
                log.warn("%s; restarting in 10 seconds", strexc(), exc_info=ex)
            else:
                log.warn("proxy_loop exited; restarting in 10 seconds")
            time.sleep(10)

    def proxy_loop(self):
        args = self.args
        poll = select.poll()  # pylint:disable=no-member
        s_rtr = rawsocket(args.if_rtr, poll=poll, promisc=args.promiscuous)
        s_wan = rawsocket(args.if_wan, poll=poll, promisc=args.promiscuous)
        socks = {s.fileno(): s for s in (s_rtr, s_wan)}
        on_poll_event = partial(self.on_poll_event, s_rtr=s_rtr, s_wan=s_wan)

        while True:
            ready = poll.poll()
            for fd, event in ready:
                on_poll_event(socks[fd], event)

    def on_poll_event(self, sock_in, event, s_rtr, s_wan):
        log = self.log
        ifname = getifname(sock_in)
        if event != select.POLLIN:  # pylint:disable=no-member
            raise IOError("[%s] unexpected poll event: %d" % (ifname, event))

        buf = sock_in.recv(2048)

        if self.args.debug_packets:
            log.debug("%s: recv %d bytes:\n%s", ifname, len(buf), strbuf(buf))

        eap = EAPFrame.from_buf(buf)
        log.debug("%s: %s", ifname, eap)

        if sock_in == s_rtr:
            sock_out = s_wan
            self.on_router_eap(eap)
            if self.should_ignore_router_eap(eap):
                log.debug("%s: ignoring %s", ifname, eap)
                return
        else:
            sock_out = s_rtr
            self.on_wan_eap(eap)

        log.info("%s: %s > %s", ifname, eap, getifname(sock_out))
        nbytes = sock_out.send(buf)
        log.debug("%s: sent %d bytes", getifname(sock_out), nbytes)


    def should_ignore_router_eap(self, eap):
        args = self.args
        if args.ignore_start and eap.is_start:
            return True
        if args.ignore_logoff and eap.is_logoff:
            return True
        if args.ignore_when_wan_up:
            return self.check_wan_is_up()
        return False

    def on_router_eap(self, eap):
        args = self.args
        if not args.set_mac:
            return

        if self.os.getmac(args.vlan) == self.os.getmac(args.if_wan) == eap.src:
            return

        self.log.info("setting mac to %s", strmac(eap.src))
        self.os.setmac(args.vlan, args.if_wan, eap.src)

        if not self.os.getmac(args.vlan) == \
               self.os.getmac(args.if_wan) == \
               eap.src:
            self.log.error("setting mac address failed")

    def on_wan_eap(self, eap):
        if not self.should_restart_dhcp(eap):
            return
        self.log.info("%s: restarting DHCP client", self.args.vlan)
        self.os.restart_dhcp_client(self.args.vlan)

    def should_restart_dhcp(self, eap):
        if self.args.restart_dhcp and eap.is_success:
            return not self.check_wan_is_up()
        return False

    def check_wan_is_up(self):
        args, log = self.args, self.log
        ipaddr = getifaddr(args.vlan)
        if ipaddr:
            log.debug("%s: %s", args.vlan, ipaddr)
            return self.ping_gateway() if args.ping_gateway else True
        log.debug("%s: no IP address", args.vlan)
        return False

    def ping_gateway(self):
        log = self.log
        ipaddr = getdefaultgatewayaddr()
        if not ipaddr:
            log.debug("ping: no default route gateway")
            return False
        rv = pingaddr(ipaddr)
        log.debug("ping: %s %s", ipaddr, "success" if rv else "failed")
        return rv

### Main

def parse_args():
    p = argparse.ArgumentParser("eap_proxy")

    # interface arguments
    p.add_argument(
        "if_wan", metavar="IF_WAN", help=
        "interface connected to the WAN uplink",
        type=network_interface)
    p.add_argument(
        "if_rtr", metavar="IF_ROUTER", help=
        "interface connected to the ISP router",
        type=network_interface)

    # checking whether WAN is up
    g = p.add_argument_group(" checking whether WAN is up")
    g.add_argument(
        "--ping-gateway", action="store_true", help=
        "normally the WAN is considered up if IF_VLAN has an IP address; "
        "this option additionally requires that there is a default route "
        "gateway that responds to a ping")

    # ignoring packet options
    g = p.add_argument_group(" ignoring router packets")
    g.add_argument(
        "--ignore-when-wan-up", action="store_true", help=
        "ignore router packets when WAN is up (see --ping-gateway)")
    g.add_argument(
        "--ignore-start", action="store_true", help=
        "always ignore EAPOL-Start from router")
    g.add_argument(
        "--ignore-logoff", action="store_true", help=
        "always ignore EAPOL-Logoff from router")

    # configuring VLAN subinterface options
    g = p.add_argument_group(" configuring VLAN subinterface on IF_WAN")
    g.add_argument(
        "--vlan", metavar="IF_VLAN", default="0", help=
        "VLAN ID or interface name of the VLAN subinterface on IF_WAN "
        "(e.g. '0' to use IF_WAN.0, 'vlan0' to use vlan0), or 'none' to use "
        "IF_WAN directly; if --vlan not specified, treated as though it were "
        "with IF_VLAN of 0")
    g.add_argument(
        "--restart-dhcp", action="store_true", help=
        "check whether WAN is up after receiving EAP-Success on IF_WAN "
        "(see --ping-gateway); if not, restart system's DHCP client on IF_VLAN")

    # setting MAC address options
    g = p.add_argument_group(" setting MAC address")
    g.add_argument(
        "--set-mac", action="store_true", help=
        "set IF_WAN and IF_VLAN's MAC (ether) address to router's MAC address")

    # daemonization options
    g = p.add_argument_group(" daemonization")
    g.add_argument(
        "--daemon", action="store_true", help=
        "become a daemon; implies --syslog")
    g.add_argument(
        "--pidfile", nargs="?", const="/var/run/eap_proxy.pid", help=
        "record pid to PIDFILE; default: /var/run/eap_proxy.pid")
    g.add_argument(
        "--syslog", action="store_true", help=
        "log to syslog instead of stderr")

    # debugging options
    g = p.add_argument_group(" debugging")
    g.add_argument(
        "--promiscuous", action="store_true", help=
        "place interfaces into promiscuous mode instead of multicast")
    g.add_argument(
        "--debug", action="store_true", help=
        "enable debug-level logging")
    g.add_argument(
        "--debug-packets", action="store_true", help=
        "print packets in hex format to assist with debugging; "
        "implies --debug")

    args = p.parse_args()
    if args.daemon:
        args.syslog = True
    if args.debug_packets:
        if args.syslog:
            p.error("--debug-packets not allowed with --syslog")
        args.debug = True
    return args


def main():
    args = parse_args()
    log = make_logger(args.syslog, args.debug)

    if os.geteuid() != 0:
        log.error("eap_proxy must be started as root")
        return 1

    try:
        set_vlan(args)
    except EnvironmentError as ex:
        log.warning(ex)

    if args.pidfile:
        pid = checkpidfile(args.pidfile)
        if pid:
            log.error("eap_proxy already running with pid %s?", pid)
            return 1

    if args.daemon:
        try:
            daemonize()
        except Exception:  # pylint:disable=broad-except
            log.exception("could not become daemon: %s", strexc())
            return 1

    # ensure cleanup (atexit, etc) occurs when we're killed via SIGTERM
    def on_sigterm(signum, __):
        log.info("exiting on signal %d", signum)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, on_sigterm)

    if args.pidfile:
        try:
            writepidfile(args.pidfile)
        except EnvironmentError:  # pylint:disable=broad-except
            log.exception("could not write pidfile: %s", strexc())

    log.info("starting with interfaces IF_WAN=%s, IF_ROUTER=%s, IF_VLAN=%s" %
             (args.if_wan, args.if_rtr, args.vlan))

    EAPProxy(args, log).proxy_forever()


if __name__ == "__main__":
    sys.exit(main())
