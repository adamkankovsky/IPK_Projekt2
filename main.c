/**
 * Project: Packet sniffer
 *
 * @author Adam Kaňkovský <xkanko00@stud.fit.vutbr.cz>
 */
#include "main.h"

/**
 * Function for finding and printing all interfaces
 */
void printAllDevs() {
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    int i = 0;
    if (pcap_findalldevs(&interfaces, error) == -1) {
        printf("error in pcap findall devs: %s", error);
        exit(EXIT_FAILURE);
    }

    printf("the interfaces present on the system are:");
    for (temp = interfaces; temp; temp = temp->next) {
        printf("\n%d  :  %s", i++, temp->name);

    }
}

/**
 * Function for printing packet with offset
 *
 * @param addr Packet.
 * @param len Packet length.
 * @return Given exit code.
 */
void packetPrinter(const u_char *addr, const int len){
    int perLine = 16;
    unsigned char buff[perLine+1];
    int i;
    const u_char *pc = addr;

    // Length checks.

    if (len == 0) {
        fprintf(stderr, "  ZERO LENGTH\n");
        exit(EXIT_FAILURE);
    }
    if (len < 0) {
        fprintf(stderr, "  NEGATIVE LENGTH: %d\n", len);
        exit(EXIT_FAILURE);
    }

    // Process every byte in the data.

    printf("\n");

    for (i = 0; i < len; i++) {
        // Multiple of perLine means new or first line (with line offset).

        if ((i % perLine) == 0) {
            // Only print previous-line ASCII buffer for lines beyond first.

            if (i != 0) printf ("  %s\n", buff);

            // Output the offset of current line.
            printf ("0x%.4x: ", i);
        }

        // Now the hex code for the specific character.
        if(i % 8 == 0 && i % 16 != 0) printf(" ");
        printf (" %02x", pc[i]);
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % perLine] = '.';
        else
            buff[i % perLine] = pc[i];
        buff[(i % perLine) + 1] = '\0';
    }
    printf ("  %s\n", buff);
}

/**
 * Function for printing source and destination ipv4 ip address
 *
 * @param packet Packet.
 */
void print_ip_header(const u_char* packet){
    struct sockaddr_in source,dest;
    struct iphdr *iph = (struct iphdr *)(packet  + sizeof(struct ether_header) );

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("src IP: %s\n",inet_ntoa(source.sin_addr));
    printf("dst IP: %s\n",inet_ntoa(dest.sin_addr));
}

/**
 * Function for printing source and destination ipv6 ip address
 *
 * @param packet Packet.
 */
void print_ip6_header(const u_char* packet){
    struct sockaddr_in6 source,dest;
    char astring[INET6_ADDRSTRLEN];
    struct ip6_hdr *iph = (struct ip6_hdr *)(packet + sizeof(struct ether_header));

    memset(&source, 0, sizeof(source));
    source.sin6_addr = iph->ip6_src;
    inet_ntop(AF_INET6, &(source.sin6_addr), astring,  INET6_ADDRSTRLEN);
    printf("src IP: %s\n", astring);

    memset(&dest, 0, sizeof(dest));
    dest.sin6_addr = iph->ip6_dst;
    inet_ntop(AF_INET6, &(dest.sin6_addr), astring,  INET6_ADDRSTRLEN);
    printf("dst IP: %s\n", astring);

}

/**
 * Function for printing source and destination port - tcp protocol
 *
 * @param packet Packet.
 * @param iphdrlen length of ip header.
 */
void print_tcp_packet(const u_char *packet, unsigned short iphdrlen){

    struct tcphdr *tcph=(struct tcphdr*)(packet + iphdrlen + sizeof(struct ether_header));

    printf("src port: %u\n",ntohs(tcph->source));
    printf("dst port: %u\n",ntohs(tcph->dest));
}

/**
 * Function for printing source and destination port - udp protocol
 *
 * @param packet Packet.
 * @param iphdrlen length of ip header.
 */
void print_udp_packet(const u_char *packet, unsigned short iphdrlen){

    struct udphdr *udph = (struct udphdr*)(packet + iphdrlen + sizeof(struct ether_header));

    printf("src port: %d\n",ntohs(udph->source));
    printf("dst port: %d\n",ntohs(udph->dest));
}

/**
 * Callback function for packet parsing and print all information by specification
 *
 * @param args Packet arguments.
 * @param header Packet header with packet information.
 * @param packet Packet
 */
void packetParser(u_char *args, const struct pcap_pkthdr *header, const u_char* packet){
    struct tm *p = localtime(&header->ts.tv_sec);
    char buf[100];
    unsigned short iphdrlen;

    size_t len = strftime(buf, sizeof buf - 1, "%FT%T%z", p);
    // move last 2 digits
    if (len > 1) {
        char minute[] = { buf[len-2], buf[len-1], '\0' };
        sprintf(buf + len - 2, ":%s", minute);
    }
    printf("timestamp: %s\n", buf);

    struct ether_header *eth = (struct ether_header *) packet;

    printf("src MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", eth->ether_shost[0] , eth->ether_shost[1] , eth->ether_shost[2] , eth->ether_shost[3] , eth->ether_shost[4] , eth->ether_shost[5] );
    printf("dst MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", eth->ether_dhost[0] , eth->ether_dhost[1] , eth->ether_dhost[2] , eth->ether_dhost[3] , eth->ether_dhost[4] , eth->ether_dhost[5] );

    printf("frame length: %d bytes\n", header->len);


    if(ntohs(eth->ether_type) == ETHERTYPE_IP){
        struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ether_header));
        switch (iph->protocol) //Check the Protocol and do accordingly...
        {
            case 1:  //ICMP Protocol
                print_ip_header(packet);
                break;
            case 6:  //TCP Protocol
                print_ip_header(packet);
                iphdrlen = iph->ihl*4;
                print_tcp_packet(packet, iphdrlen);
                break;

            case 17: //UDP Protocol
                print_ip_header(packet);
                iphdrlen = iph->ihl*4;
                print_udp_packet(packet, iphdrlen);
                break;

            default: //Some Other Protocol like ARP etc.
                break;
        }
    }else if(ntohs(eth->ether_type) == ETHERTYPE_IPV6){
        struct ip6_hdr *iph = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        switch (iph->ip6_ctlun.ip6_un1.ip6_un1_nxt) //Check the Protocol and do accordingly...
        {
            case 1:  //ICMP Protocol
                print_ip6_header(packet);
                break;
            case 6:  //TCP Protocol
                print_ip6_header(packet);
                iphdrlen = sizeof(struct ip6_hdr);
                print_tcp_packet(packet, iphdrlen);
                break;

            case 17: //UDP Protocol
                print_ip6_header(packet);
                iphdrlen = sizeof(struct ip6_hdr);
                print_udp_packet(packet, iphdrlen);
                break;

            default: //Some Other Protocol like ARP etc.
                break;
        }
    }else if(ntohs(eth->ether_type) == ETHERTYPE_ARP){
    }
    packetPrinter(packet, (int)header->len);
}

/**
 * Fuction with pcap_loop
 *
 * @param handle Session handle.
 * @param iphdrlen the amount of packet we are looking for.
 */
void getPackets(pcap_t* handle, int packets){
    if(pcap_loop(handle, packets, packetParser, 0) < 0){
        fprintf(stderr, "Error: Couldn't install filter %s\n", pcap_geterr(handle));
    }
}

/**
 * Function for open session and apply filter on it
 *
 * @param dev Device for session.
 * @param filter_exp filter.
 * @return Session handle
 */
pcap_t* socket_open(char* dev, char* filter_exp){
    pcap_t *handle;		/* Session handle */
    struct bpf_program fp;		/* The compiled filter expression */
    char error[PCAP_ERRBUF_SIZE];	/* Error string */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */
    if (pcap_lookupnet(dev, &net, &mask, error) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, error);
    if (handle == NULL) {
        fprintf(stderr, "Error: cant open device: %s \n%s", dev, error);
        exit(2);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error: could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error: Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }
    return handle;
}
/**
 * Main project function
 *
 * @param argc Arguments count.
 * @param argv Arguments.
 * @return Session handle
 */
int main(int argc, char **argv) {
    int c = -1 ;
    char *dev = NULL;
    int printed = 0;
    int tcp = 0;
    int udp = 0;
    int arp = 0;
    int icmp = 0;
    int packets = 1;
    char port[20] = "";
    char filter_exp[100] = "";
    while (1) {
        int option_index = 0;
        c = getopt_long(argc, argv, "i::p:tun:", long_options, &option_index);
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'i':
                if (optarg == NULL && optind < argc
                    && argv[optind][0] != '-')
                {
                    optarg = argv[optind++];
                }
                if(optarg == NULL){
                    printAllDevs();
                    printed = 1;
                }else{
                    dev = optarg;
                }
                break;
            case 'p':
                if (optarg != NULL){
                    if(atoi(optarg)){
                        int p = atoi(optarg);
                        if (!(p > 0 && p < 65536)){
                            printf("ERROR: port in bad range");
                            exit(EXIT_FAILURE);
                        }else{
                            sprintf(port, "port %d", p);
                        }
                    }else{
                        printf("ERROR: port must be number");
                        exit(EXIT_FAILURE);
                    }
                }
                break;
            case 't':
                tcp = 1;
                break;
            case 'u':
                udp = 1;
                break;
            case 'c':
                icmp = 1;
                break;
            case 'a':
                arp = 1;
                break;
            case 'n':
                if (optarg != NULL){
                    if(atoi(optarg)){
                        packets = atoi(optarg);
                    }else{
                        printf("ERROR: packet number must be name");
                        exit(EXIT_FAILURE);
                    }
                }
                break;
            case '?':
                //get-opt error printed already
                break;
            default:
                abort();
        }
    }
    if(tcp == 1){
        strcat(filter_exp, "tcp");
        if (strcmp(port, "") != 0){
            strcat(filter_exp, " ");
            strcat(filter_exp, port);
        }
    }
    if(udp == 1){
        if(strcmp(filter_exp, "") == 0){
            strcat(filter_exp, "udp");
        }else{
            strcat(filter_exp, " or udp");
        }
        if (strcmp(port, "") != 0){
            strcat(filter_exp, " ");
            strcat(filter_exp, port);
        }
    }
    if(icmp == 1){
        if(strcmp(filter_exp, "") == 0){
            strcat(filter_exp, "icmp");
        }else{
            strcat(filter_exp, " or icmp");
        }
    }
    if(arp == 1){
        if(strcmp(filter_exp, "") == 0){
            strcat(filter_exp, "arp");
        }else{
            strcat(filter_exp, " or arp");
        }
    }
    if(icmp == 0 && arp == 0 && udp == 0 && tcp == 0 && strcmp(port, "") != 0){
        strcat(filter_exp, "tcp");
        strcat(filter_exp, " ");
        strcat(filter_exp, port);
        strcat(filter_exp, " or udp");
        strcat(filter_exp, " ");
        strcat(filter_exp, port);
        strcat(filter_exp, " or icmp");
        strcat(filter_exp, " or arp");
    }else if(icmp == 0 && arp == 0 && udp == 0 && tcp == 0 && strcmp(port, "") == 0){
        strcat(filter_exp, "tcp");
        strcat(filter_exp, " or udp");
        strcat(filter_exp, " or icmp");
        strcat(filter_exp, " or arp");
    }

    if(dev == NULL || strcmp(dev, "") == 0){
        if (printed == 0){
            printAllDevs();
        }
    }else{
        pcap_t *handle = socket_open(dev, filter_exp);
        getPackets(handle, packets);
        pcap_close(handle);
        return(0);
    }
}