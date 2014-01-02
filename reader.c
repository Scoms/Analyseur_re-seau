//reader.c
#include "reader.h"

#define LOW 1
#define MID 2
#define HIG 3

//Valeurs  
#define IP 8
#define ARP 1544
#define RARP 56710

//Protocoles
#define TCP_PROT 6
#define UDP_PROT 11


void packetDisplay(const u_char *packet,int length,int verbose){

	if(verbose == HIG){
		readU_Char(packet,length,verbose);
	}

	struct ether_header *ethernet;
	struct ip *ip;
	struct arp *arp;

	int size_ethernet = sizeof(struct ether_header);

	ethernet = (struct ether_header*)(packet);;
	int eth_type = readEthernet(ethernet,verbose);
	//printf("%x\n",eth_type );

	if(eth_type == IP){
		ip = (struct ip*)(packet + size_ethernet);
		readIP(ip,verbose);
	}
	else if(eth_type == ARP){
		arp = (struct arp*)(packet + size_ethernet);
		readARP(arp,verbose);
	}
	else if (eth_type == RARP){
		printf("RARP\n");
	}
	else{
		printf("---- ERROR ---\n");
	}
}

void readARP(struct arp* arp, int verbose){
	printf("ARP\n");
	if(verbose == 3){
		printf("  Hard Type : %i\n",arp->htype);
		printf("  Prot Type : %i\n",arp->ptype);
		printf("  Hard Add len : %x\n",arp->hlen);
		printf("  Hard Prot Len : %x\n",arp->plen);
		printf("  Ope Code : %i\n",arp->oper);
		printf("  Sender hardware address :");
		readU_Char(arp->sha,sizeof(arp->sha),verbose);
		printf("  Sender IP address :");
		ip_address * spa = (ip_address *)arp->spa;
		printf("%d.%d.%d.%d\n",spa->byte1,spa->byte2,spa->byte3,spa->byte4);
		//readU_Char(arp->spa,sizeof(arp->spa),verbose);
		printf("  Target hardware address :");
		readU_Char(arp->tha,sizeof(arp->tha),verbose);
		printf("  Target IP address :");
		ip_address * tpa = (ip_address *)arp->tpa;
		printf("%d.%d.%d.%d\n",tpa->byte1,tpa->byte2,tpa->byte3,tpa->byte4);	
	}
	/*
	printf("  Sender hardware address : %u\n",arp->sha[6]);
	printf("  Sender IP address : %x\n",arp->spa[4]);
	printf("  Target hardware address : %x\n",arp->tha[6]);
	printf("  Target IP address: %x\n",arp->tpa[4]);
	*/
}

void readU_Char(const u_char * toRead,int length,int verbose){
	int i = 0;
	for(i=0; i < length; i++){
		printf("%02x ", (toRead[i])) ;
	}
	printf("\n");
}

int readEthernet(struct ether_header* ethernet,int verbose){
	printf("\nEthernet : \n");
	if(verbose == HIG){
		printf("  Destination : ");
		readU_Char(ethernet->ether_dhost,sizeof(ethernet->ether_dhost),verbose);
		printf("  Source : ");
		readU_Char(ethernet->ether_shost,sizeof(ethernet->ether_shost),verbose);
	}
	if(verbose == MID){
		printf("  Destination : ");
		readU_Char(ethernet->ether_dhost,sizeof(ethernet->ether_dhost),verbose);
		printf("  Source : ");
		readU_Char(ethernet->ether_shost,sizeof(ethernet->ether_shost),verbose);
	}
	if(verbose == LOW){

	}
	// printf("%i\n", ethernet->ether_type);
	return ethernet->ether_type;
}


void readIP(struct ip* ip,int verbose){
	printf("IP : \n");
	if(verbose == 3){
		printf("  Version : %x\n",ip->ip_v);	
		printf("  HL : %x\n",ip->ip_hl);	
		printf("  Total length : %x\n",ip->ip_len);	
		printf("  ID : %x\n",ip->ip_id);	
		printf("  Offset : %x\n",ip->ip_off);	
		printf("  TOS : %x\n",ip->ip_tos);	
		printf("  Protocole : %x\n",ip->ip_p);	
		printf("  Total : %x\n",ip->ip_ttl);	
		printf("  Checksum : %x\n",ip->ip_sum);	
		printf("  IP src : %s\n",inet_ntoa(ip->ip_src));	
		printf("  IP dest : %s\n",inet_ntoa(ip->ip_dst));	
	}
	if(verbose == 2){
		if(ip->ip_p == TCP_PROT){
			printf("  %s\n", "Protocole TCP");
		}
		else if(ip->ip_p == UDP_PROT){
			printf("  %s\n", "Protocole UDP");
		}
	}

	struct tcphdr* tcp;
	struct udphdr* udp;
	switch(ip->ip_p){
		case TCP_PROT:
			tcp = (struct tcphdr*)(ip + sizeof(ip));
			readTCP(tcp,verbose);
			break;
		case UDP_PROT:
			udp = (struct udphdr*)(ip + sizeof(ip));
			readUDP(udp,verbose);
			break;
		default:
			printf("Protocole non traité : %i\n",ip->ip_p);
			break;
	}
}

void readUDP(struct udphdr * udp, int verbose){
	printf("UDP : \n");
	if(verbose == 3){
		printf("Source port : %d\n",udp->uh_sport );
		printf("Destination port : %d\n",udp->uh_dport );
		printf("Length : %d\n",udp->uh_ulen );
		printf("Checksum : %d\n",udp->uh_sum );
	}
}

void readTCP(struct tcphdr* tcp,int verbose){
	printf("TCP : \n");	
	if(verbose == 3){
		printf("  Port dst : %d\n",(tcp->th_sport));	
		printf("  Port src : %d\n",tcp->th_dport);	
		printf("  seq : %x\n",tcp->th_seq);	
		printf("  ack_seq : %x\n",tcp->th_ack);
		printf("  Window : %x\n",tcp->th_win);	
		printf("  Checksum : %x\n",tcp->th_sum);	
		printf("  Urgent pointer : %x\n",tcp->th_urp);	
		printf("  Flags : %x\n",tcp->th_flags);	
		printf("  Data Offset : %x\n",tcp->th_off);	
	}
}

void getHour(const struct pcap_pkthdr* header,int verbose){
	struct timeval tv;
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];
	gettimeofday(&tv, NULL);
	nowtime = tv.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S",nowtm);
	snprintf(buf, sizeof buf, "%s.%06d", tmbuf, tv.tv_usec);
	
	if(verbose == 1)
		printf("%s\n",buf );
	else
		printf("Message reçu à %s\n",buf );
}

void getHeaderLength(const struct pcap_pkthdr* header,int verbose){
	if(verbose != 1)
		printf("Taille du packet : %d\n",header->len);
}