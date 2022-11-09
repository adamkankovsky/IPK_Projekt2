# IPK_Projekt
## Install:
### For installation use this command in project directory:
```
make
```
## Usage:
<p>./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-
n num}</p>
<p>--interface - use with interface name or without for print all active interfaces</p>
<p>-p number - use for filter packets with port number same as defined</p>
<p>--tcp - filter tcp packets</p>
<p>--udp - filter udp packets</p>
<p>--arp - filter arp frames</p>
<p>--icmp - filter icmp packets</p>
<p>-n number - use for print number of packets same as defined</p>
<b>arguments in compound bracket are optional others are mandatory</b>