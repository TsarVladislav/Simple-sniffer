#ifndef SNIFFER_H
#define SNIFFER_H

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <linux/if_packet.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#define MAXPACKETSIZE 65536

static volatile int running = 1;
void end_prog();
void print_data(unsigned char* data , int size);
void print_ip_header(unsigned char *buffer, int size);
void print_ethernet_header(unsigned char* buffer, int size);
void print_tcp_packet(unsigned char *buffer, int size);
void print_udp_packet(unsigned char *buffer, int size);


static const char *protocol_name(unsigned int protocol);
static const char *header_type(unsigned int hatype);
static const char *packet_type(unsigned int pkttype);
#endif
