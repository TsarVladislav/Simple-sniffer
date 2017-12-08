#include "sniffer.h"

int main(void)
{

    int sockfd;
    unsigned char *buffer;
    time_t rawtime;
    struct tm *timeinfo;
    socklen_t saddr_size;
    int datasize;
    struct sockaddr_ll addr;

    sockfd = socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL));

    if(sockfd < 0) {
        perror("socket...");
        return 1;
    }
    signal(SIGINT, end_prog);
    buffer = malloc(MAXPACKETSIZE);

    if (buffer == 0) {
        printf("Can't malloc...\n");
        return 1;
    }
    
    time(&rawtime);
    while (running) {
        memset(buffer, 0, MAXPACKETSIZE);
        memset(&addr, 0, sizeof addr);
        saddr_size = sizeof(addr);
        datasize  = recvfrom(sockfd, buffer, MAXPACKETSIZE, 0, (struct sockaddr *)&addr, &saddr_size);

        if (datasize == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom...");
            break;
        }
        timeinfo = localtime(&rawtime);
        printf("\n\n--------------------------\n%s--------------------------\n\n", asctime(timeinfo) );
        printf("Received %d bytes\n", datasize);
        printf("\t Protocol: %s\n", protocol_name(htons(addr.sll_protocol)));

        printf("\t Interface: %d\n", addr.sll_ifindex);
        printf("\t Header type: %s\n", header_type(addr.sll_hatype));
        printf("\t Packet type: %s\n", packet_type(addr.sll_pkttype));


        if (addr.sll_hatype == 1) {
            print_ethernet_header(buffer, datasize);
            printf("-----------------------------------------\n");
        } else {
            printf("The data-link protocol is not implemented\n");
        }
    }

    printf("Ctrl-C was pressed, finishing...\n");
    close(sockfd);
    free(buffer);
    return 0;
}


void end_prog(){
    running = 0;
}
void print_data(unsigned char* data , int size)
{
    int i, j;
    for(i = 0 ; i < size; i++){
        if(i != 0 && i % 16 == 0){
            printf("     ");
            for(j = i - 16; j < i; j++){
                if(data[j] >= 32 && data[j] <= 128){
                    printf("%c",(unsigned char)data[j]);
                }else{
                    printf(".");
                }
            }
            printf("\n");
        } 
        if(i % 16 == 0){
            printf("\t");
        }

        printf(" %02X",(unsigned int)data[i]);
        if(i == size - 1){
            for(j = 0; j < 15 - i % 16;j++) {
                printf("   ");
            }
            printf("     ");
            for(j= i - i % 16 ; j <= i; j++){
                if(data[j] >= 32 && data[j] <= 128) {
                  printf("%c",(unsigned char)data[j]);
                } else{
                  printf( ".");
                }
            }
            printf("\n");
        }
    }
}

void print_ethernet_header(unsigned char* buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr *) buffer;
    printf("Ethernet Header\n");
    printf("\t Destination Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
         eth->h_dest[0],
         eth->h_dest[1],
         eth->h_dest[2],
         eth->h_dest[3],
         eth->h_dest[4],
         eth->h_dest[5] );
    printf("\t Source Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
         eth->h_source[0],
         eth->h_source[1],
         eth->h_source[2],
         eth->h_source[3],
         eth->h_source[4],
         eth->h_source[5] );

    /* https://en.wikipedia.org/wiki/EtherType#Examples */
    /* для всяких TCP-UDP есть /etc/protocols, а тут как быть? */

    printf("Ethernet Header(Hex)\n");
    print_data(buffer, sizeof(struct ethhdr));
    switch(ntohs(eth->h_proto)){
        case 0x0800: /* IPv4 */
            print_ip_header(buffer, size);
            break;
        default:
            printf("\t This Internet layer protocol isn't implemented(0x%x)\n", ntohs(eth->h_proto));
            break;
    }
}

void print_ip_header(unsigned char *buffer, int size)
{
    struct sockaddr_in source, dest;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(struct sockaddr_in));
    memset(&dest, 0, sizeof(struct sockaddr_in));

    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;

    printf("IP header\n");
    printf("\t IP Version: %u\n", iph->version);
    printf("\t IHL(bytes): %u\n", iph->ihl * 4);
    printf("\t ToS: %u\n", iph->tos);
    printf("\t Total length: %u\n", ntohs(iph->tot_len));
    printf("\t ID: %u\n",ntohs(iph->id));
    printf("\t TTL: %u\n", iph->ttl);
    printf("\t Protocol: %u\n", iph->protocol);
    printf("\t Checksum: 0x%.4x\n", ntohs(iph->check));
    printf("\t IP Source: %s\n", inet_ntoa(source.sin_addr));
    printf("\t IP Destination: %s\n", inet_ntoa(dest.sin_addr));

    printf("IP Header(Hex)\n");
    print_data(buffer,iph->ihl * 4);
    switch (iph->protocol) {
        case 6: /* TCP */
            print_tcp_packet(buffer, size);
            break;
        case 17: /* UDP */
            print_udp_packet(buffer, size);
            break;
       default:
            printf("\t This Transport layer protocol isn't implemented(0x%x)\n", iph->protocol);
            break;
    }
}

void print_tcp_packet(unsigned char *buffer, int size)
{
    int iplen;
    int header_size; 
    struct tcphdr *tcph = NULL;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iplen = iph->ihl * 4;
    /* получаю длину IP-заголовка */
    tcph = (struct tcphdr *)(buffer + iplen + sizeof(struct ethhdr));
    printf("TCP header\n");
    printf("\t Source port: %u\n", ntohs(tcph->source));
    printf("\t Destination port: %u\n", ntohs(tcph->dest));
    /* какие-то адские значения */
    printf("\t Sequence number(SN): %u\n", ntohl(tcph->seq));
    printf("\t ACK SN: %u\n", ntohl(tcph->ack_seq));
    printf("\t Header length(bytes): %u\n", tcph->doff * 4);
    printf("\t Urgent flag: %u\n", tcph->urg);
    printf("\t ACK flag: %u\n", tcph->ack);
    printf("\t Push flag: %u\n", tcph->psh);
    printf("\t Reset flag: %u\n",tcph->rst);
    printf("\t SYN flag: %u\n",     tcph->syn);
    printf("\t FIN flag: %u\n", tcph->fin);
    printf("\t Window: %u\n", htons(tcph->window));
    printf("\t Checksum: 0x%.4x\n", ntohs(tcph->check));
    printf("\t Urgent: %u\n", ntohs(tcph->urg_ptr));

    header_size =  sizeof(struct ethhdr) + iplen + tcph->doff*4;

    printf("TCP Header(Hex)\n");
    print_data(buffer+iplen,tcph->doff*4);

    printf("Data Payload(Hex)\n");
    print_data(buffer + header_size , size - header_size );
}

void print_udp_packet(unsigned char *buffer, int size)
{

    int iplen;
    int header_size; 
    struct udphdr *udph = NULL;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iplen = iph->ihl * 4;
    udph = (struct udphdr *)(buffer + iplen + sizeof(struct ethhdr));
    printf("UDP header\n");
    printf("\t Source port: %u\n", ntohs(udph->source));
    printf("\t Destination port: %u\n", ntohs(udph->dest));
    printf("\t Length : %u\n", ntohs(udph->len));
    printf("\t Checksum: 0x%.4x\n", ntohs(udph->check));

    header_size =  sizeof(struct ethhdr) + iplen + sizeof udph;
    printf("UDP Header(Hex)\n");
    print_data(buffer+iplen, sizeof(udph));
    printf("Data Payload(Hex)\n");    
    print_data(buffer + header_size , size - header_size );

}

static const char *packet_type(unsigned int pkttype)
{
    static char buffer[16];
    switch (pkttype) {
    case PACKET_HOST:
        return "PACKET_HOST";
    case PACKET_BROADCAST:
        return "PACKET_BROADCAST";
    case PACKET_MULTICAST:
        return "PACKET_MULTICAST";
    case PACKET_OTHERHOST:
        return "PACKET_OTHERHOST";
    case PACKET_OUTGOING:
        return "PACKET_OUTGOING";
    default:
        snprintf(buffer, sizeof buffer, "0x%02x", pkttype);
        return (const char *)buffer;
    }
}
static const char *header_type(unsigned int hatype)
{
    static char buffer[16];
    switch (hatype) {
    case 1:
        return "ARPHRD_ETHER: Ethernet 10Mbps";
    case 2: 
        return "ARPHRD_EETHER: Experimental Ethernet";
    case 768: 
        return "ARPHRD_TUNNEL: IP Tunnel";
    case 772: 
        return "ARPHRD_LOOP: Loopback";
    default:
        snprintf(buffer, sizeof buffer, "0x%04x", hatype);
        return buffer;
    }
}
static const char *protocol_name(unsigned int protocol)
{
    static char buffer[16];
    switch (protocol & 0xFFFFU) {
    case 0x0001:
        return "ETH_P_802_3";
    case 0x0002:
        return "ETH_P_AX25";
    case 0x0003:
        return "ETH_P_ALL";
    case 0x0060:
        return "ETH_P_LOOP";
    case 0x0800:
        return "ETH_P_IP";
    case 0x0806:
        return "ETH_P_ARP";
    case 0x8100:
        return "ETH_P_8021Q (802.1Q VLAN)";
    case 0x88A8:
        return "ETH_P_8021AD (802.1AD VLAN)";
    default:
        snprintf(buffer, sizeof buffer, "0x%04x", protocol & 0xFFFFU);
        return (const char *)buffer;
    }
}
