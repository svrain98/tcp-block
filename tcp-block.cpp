#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <libnet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
using namespace std;
void usage() {
    printf("syntax: tcp-block <interface> <pattern>\n");
    printf("sample: tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}
void print_data(const u_char* data,int data_len){

}
int check_pattern(char* pattern, int pattern_len, const u_char* data, int data_len){
    for(int i=0;i<data_len;i++){
        unsigned char* t = (unsigned char *)(data);
        const char*k = (const char*)t;
        if(strncmp(k+i,pattern,pattern_len)==0){
            printf("success\n");
            return 3;
        }
    }
}

uint16_t tcp_checksum(struct libnet_ipv4_hdr *ip,struct libnet_tcp_hdr *tcp,int packet_len){
    uint32_t cksum=0;
    uint16_t newip[100]={0,};
    uint16_t newtcp[100]={0,};
    memcpy(newip,ip,sizeof(struct libnet_ipv4_hdr));
    memcpy(newtcp,tcp,packet_len-14-20);
    uint16_t idx=0;
    for (int i=0;i<4;i++){
        idx=(uint16_t)(newip[i+6]);
        cksum+=idx;
    }
    idx=(uint16_t)htons(6);
    cksum+=idx;
    uint16_t len=(uint16_t)htons(packet_len-(14+20));
    int my_len=packet_len-(14+20);
    cksum+=len;
    for(int i=0;i<my_len/2;i++){
        if(i!=8){
        idx=(uint16_t)newtcp[i];
        cksum+=idx;
        }
    }
    while(cksum >> 16) {
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    }
    uint16_t last=(uint16_t)cksum;
    return ~last;
}

uint16_t ip_checksum(struct libnet_ipv4_hdr *ip){
    uint32_t cksum=0;
    uint16_t newip[100]={0,};
    memcpy(newip,ip,sizeof(struct libnet_ipv4_hdr));
    uint16_t idx=0;
    
    for(int i=0;i<10;i++){
        if(i==5)
        continue;
        idx=(uint16_t)newip[i];
        cksum+=idx;
    }
    while(cksum>>16){
        cksum= (cksum &0xFFFF)+(cksum>>16);
    }
    uint16_t last=cksum;
    return ~last;
}

void block_forward(pcap_t* handle, const u_char* packet, int packet_len){
    u_char newpacket[54]={0,};
    struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
    eth= (struct libnet_ethernet_hdr*)packet;
	ip= (struct libnet_ipv4_hdr*)(packet+14);
	tcp=(struct libnet_tcp_hdr*)(packet+14+ip->ip_hl*4);

    struct libnet_ethernet_hdr *neweth;
	struct libnet_ipv4_hdr *newip;
	struct libnet_tcp_hdr *newtcp;

	neweth= (struct libnet_ethernet_hdr*)newpacket;
	newip= (struct libnet_ipv4_hdr*)(newpacket+14);
	newtcp=(struct libnet_tcp_hdr*)(newpacket+14+ip->ip_hl*4);
    memcpy(neweth,eth,14);
    memcpy(newip,ip,ip->ip_hl*4);
    newip->ip_len=ntohs(0x28);
    memcpy(newtcp,tcp,20);
    newtcp->th_flags|=0x04;
    newtcp->th_seq = htonl(ntohl(tcp->th_seq)+packet_len-54);
    newtcp->th_ack= tcp->th_ack;
    uint16_t tcp_cksum=tcp_checksum(newip,newtcp,54);
    newtcp->th_sum=(tcp_cksum);
    uint16_t ip_cksum=ip_checksum(newip);
    newip->ip_sum=ip_cksum;
    
    int res = pcap_sendpacket(handle, (const u_char*)newpacket, 54);
    if (res != 0) fprintf(stderr, "Forward packet error!\n");
}
void block_backward(pcap_t* handle, const u_char* packet, int packet_len)
{
    u_char newpacket[packet_len]={0,};
    struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
    eth= (struct libnet_ethernet_hdr*)packet;
	ip= (struct libnet_ipv4_hdr*)(packet+14);
	tcp=(struct libnet_tcp_hdr*)(packet+14+ip->ip_hl*4);

    struct libnet_ethernet_hdr *neweth;
	struct libnet_ipv4_hdr *newip;
	struct libnet_tcp_hdr *newtcp;

	neweth= (struct libnet_ethernet_hdr*)newpacket;
	newip= (struct libnet_ipv4_hdr*)(newpacket+14);
	newtcp=(struct libnet_tcp_hdr*)(newpacket+14+ip->ip_hl*4);
    memcpy(neweth,eth,14);
    for(int i=0; i<6; i++){
                neweth->ether_dhost[i] = eth->ether_shost[i];
                neweth->ether_shost[i] = eth->ether_dhost[i];
    }
    
    memcpy(newip,ip,ip->ip_hl*4);
    memcpy(newpacket+14+12,((u_char*)ip)+16,4);
    memcpy(newpacket+14+16,((u_char*)ip)+12,4);
    memcpy(newtcp,tcp,tcp->th_off*4);
    newtcp->th_flags|=0x01;
    u_char* msg=(u_char*)"blocked!!!";
    memcpy(newpacket+14+20+20,msg,10);
    int pac_len=54+sizeof(msg);
    newtcp->th_sport=tcp->th_dport;
    newtcp->th_dport=tcp->th_sport;
    newip->ip_len=ntohs(50);
    newtcp->th_ack = htonl(ntohl(tcp->th_seq)+packet_len-54);
    newtcp->th_seq= tcp->th_ack;
    uint16_t tcp_cksum=tcp_checksum(newip,newtcp,64);
    newtcp->th_sum=(tcp_cksum);
    uint16_t ip_cksum=ip_checksum(newip);
    newip->ip_sum=ip_cksum;
        
    int res = pcap_sendpacket(handle, (const u_char*)newpacket, 64);
    if (res != 0) fprintf(stderr, "Forward packet error!\n");
}
void block(pcap_t* handle,char* dev,char* pattern, int pattern_len)
{
    int i=0;
    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        int packet_len=header->caplen;
        struct libnet_ethernet_hdr *eth;
	    struct libnet_ipv4_hdr *ip;
	    struct libnet_tcp_hdr *tcp;
	    eth= (struct libnet_ethernet_hdr*)packet;
	    ip= (struct libnet_ipv4_hdr*)(packet+14);
	    tcp=(struct libnet_tcp_hdr*)(packet+14+ip->ip_hl*4);
	    const u_char *data= packet + 14+ ip->ip_hl*4 + tcp->th_off*4;
        int data_len=packet_len-14-(ip->ip_hl*4 + tcp->th_off*4);
        print_data(data,data_len);
        if(check_pattern(pattern, pattern_len,data, data_len)!=3) continue;
        {
            block_forward(handle,packet,packet_len);
            block_backward(handle,packet,packet_len);
        }

    }
    pcap_close(handle);
}
int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }
    char *pattern_0=argv[2];
    int pattern_len=strlen(pattern_0);
    char *pattern=new char[pattern_len];
    memcpy(pattern,pattern_0,pattern_len);
    char *dev=argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return 0;
    }
    block(handle,dev, pattern, pattern_len);
    //block()
    //char errbuf[PCAP_ERRBUF_SIZE];
    //pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    //if (handle == nullptr) {
    //   fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
    //    return -1;
    //}
   
    //pcap_close(handle);
}
