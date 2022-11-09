/**
 * Project: Packet sniffer
 *
 * @author Adam Kaňkovský <xkanko00@stud.fit.vutbr.cz>
 */
#include <stdio.h>
#include <getopt.h> //library for argument parsing
#include <stdlib.h>
#include <pcap.h> //library for work with interfaces
#include <ctype.h>
#include <string.h>
#include <time.h> //library for time
#include <netinet/ip.h> //ip header structure
#include <netinet/ip6.h> //ip6 header structure
#include <netinet/tcp.h> //tcp header structure
#include <netinet/udp.h> //udp header structure
#include <netinet/if_ether.h> //ethernet header structure

//structure for arguments getopt
static struct option long_options[] =
        {
                {"interface", optional_argument, 0, 'i'},
                {"port",      required_argument, 0, 'p'},
                {"tcp",       no_argument,       0, 't'},
                {"udp",       no_argument,       0, 'u'},
                {"icmp",      no_argument,       0, 'c'},
                {"arp",       no_argument,       0, 'a'},
                {"n_packets", required_argument, 0, 'n'},
                {0, 0,                           0, 0}
        };