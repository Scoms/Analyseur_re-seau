//reader.c
#include "reader.h"

#define LOW 1
#define MID 2
#define HIG 3

//Valeurs  
#define IP 8
#define ARP 1544
#define RARP 56710
#define BIG 1
#define SMALL 0

//Protocoles
#define TCP_PROT 6
#define UDP_PROT 11

#define HTTP 80
#define HTTPS 443
#define DHCP1 44
#define DHCP2 43
#define DNS 53
#define FTP_ETA 20
#define FTP_TRANS 21
#define POP2 109
#define POP3 110
#define SMTP 25
#define IMAP 143
#define IMAPSSL 993
#define SCTP 22



void packetDisplay(const struct pcap_pkthdr * header,const u_char *packet,int verbose){

	if(verbose == HIG){
		readU_Char(packet,header->len,BIG);
	}

	struct ether_header *ethernet;
	struct ip *ip;
	struct arp *arp;

	int size_ethernet = sizeof(struct ether_header);

	ethernet = (struct ether_header*)(packet);;
	int eth_type = readEthernet(ethernet,verbose);
	u_char destPort;

	if(eth_type == IP){
		readIP(header,packet,size_ethernet,verbose);
		//printf("%x\n",destPort);
	}
	else if(eth_type == ARP){
		arp = (struct arp*)(packet + size_ethernet);
		readARP(arp,verbose);
		//readApplicatif("UNKNOW FOR NOW",header,packet, (sizeof(*arp)+sizeof(*ip)),verbose);		
	}
	else if (eth_type == RARP){
		printf("RARP\n");
	}
	else{
		printf("---- ERROR ---\n");
	}
}

void readARP(struct arp* arp, int verbose){
	if(verbose == 3){
		printf("ARP\n");
		printf("  Hard Type : %i\n",arp->htype);
		printf("  Prot Type : %i\n",arp->ptype);
		printf("  Hard Add len : %x\n",arp->hlen);
		printf("  Hard Prot Len : %x\n",arp->plen);
		printf("  Ope Code : %i\n",arp->oper);
		printf("  Sender hardware address :");
		readU_Char(arp->sha,sizeof(arp->sha),SMALL);
		printf("  Sender IP address :");
		ip_address * spa = (ip_address *)arp->spa;
		printf("%d.%d.%d.%d\n",spa->byte1,spa->byte2,spa->byte3,spa->byte4);
		printf("  Target hardware address :");
		readU_Char(arp->tha,sizeof(arp->tha),SMALL);
		printf("  Target IP address :");
		ip_address * tpa = (ip_address *)arp->tpa;
		printf("%d.%d.%d.%d\n",tpa->byte1,tpa->byte2,tpa->byte3,tpa->byte4);	
	}
	else if (verbose == MID){
		printf("ARP\n");
		printf("  Sender hardware address :");
		readU_Char(arp->sha,sizeof(arp->sha),SMALL);
		printf("  Sender IP address :");
		ip_address * spa = (ip_address *)arp->spa;
		printf("%d.%d.%d.%d\n",spa->byte1,spa->byte2,spa->byte3,spa->byte4);
		printf("  Target hardware address :");
		readU_Char(arp->tha,sizeof(arp->tha),SMALL);
		printf("  Target IP address :");
		ip_address * tpa = (ip_address *)arp->tpa;
		printf("%d.%d.%d.%d\n",tpa->byte1,tpa->byte2,tpa->byte3,tpa->byte4);
	}
	else{
		printf("ARP");
	}
}

// permet d'afficher des u_char proprement
void readU_Char(const u_char * toRead,int length,int type){
	int i = 0;
	for(i=0; i < length; i++){

		if(type == BIG)
			if(i%16 == 0)
				printf("\n");
				
		printf("%02x", (toRead[i])) ;
		if(type == SMALL)
			printf(" ");

		else
			if(i%2 == 1 && i != 0)
				printf(" ");
	}
	printf("\n");
}

int readEthernet(struct ether_header* ethernet,int verbose){
	if(verbose == HIG || verbose == MID){
		printf("\nEthernet : \n");
		printf("  Destination : ");
		readU_Char(ethernet->ether_dhost,sizeof(ethernet->ether_dhost),SMALL);
		printf("  Source : ");
		readU_Char(ethernet->ether_shost,sizeof(ethernet->ether_shost),SMALL);
	}
	if(verbose == LOW){
		printf("Ethernet, ");
	}
	// printf("%i\n", ethernet->ether_type);
	return ethernet->ether_type;
}


void readIP(const struct pcap_pkthdr* header,const u_char* packet,int offset,int verbose){
	struct ip * ip = (struct ip*)(packet + offset);
	if(verbose == 3){
		printf("IP : \n");
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
	else if(verbose == 2){
		printf("IP : \n");
	}
	if(verbose == 1){
		printf("IP, ");
	}
	
	struct tcphdr* tcp;
	struct udphdr* udp;
	switch(ip->ip_p){
		case TCP_PROT:
			// tcp = (struct tcphdr*)(packet + sizeof(*ip) + offset);
			// readTCP(tcp,verbose);
			offset += sizeof(*ip);
			readTCP(header,packet,offset,verbose);
			break;
		case UDP_PROT:
			udp = (struct udphdr*)(ip + sizeof(ip));
			readUDP(udp,verbose);
			offset += sizeof(*udp);

			char * appli = "Applicatif";
			if(udp->uh_sport == DHCP1 || udp->uh_sport == DHCP2)
				appli = "DHCP";

			readApplicatif("Applicatif",header,packet,offset,SMALL);
			break;
		default:
			printf("Protocole non traité : %i\n",ip->ip_p);
			break;
	}
}

void readUDP(struct udphdr * udp, int verbose){
	if(verbose == 3){
		printf("UDP : \n");
		printf("Source port : %d\n",udp->uh_sport );
		printf("Destination port : %d\n",udp->uh_dport );
		printf("Length : %d\n",udp->uh_ulen );
		printf("Checksum : %d\n",udp->uh_sum );
	}
	else if(verbose == 2){
		printf("UDP : portdest -> %d , portsrc -> %d\n",udp->uh_dport,udp->uh_sport);
	}
	else{
		printf("UDP, ");
	}
}

//Lecture du segment TCP
void readTCP(const struct pcap_pkthdr * header, const u_char * packet,int offset,int verbose){
	struct tcphdr* tcp= (struct tcphdr*)(packet + offset); 
	if(verbose == 3){
		printf("TCP : \n");	
		printf("  Port src : %d\n",ntohs(tcp->th_sport));
		printf("  Port dest : %d\n",ntohs(tcp->th_dport));
		printf("  seq : %d\n",ntohs(tcp->th_seq));	
		printf("  ack_seq : %d\n",ntohs(tcp->th_ack));
		printf("  Window : %d\n",ntohs(tcp->th_win));	
		printf("  Flags : %d\n",ntohs(tcp->th_flags));	
		printf("  Data Offset : %d\n",ntohs(tcp->th_off));	
		printf("  Checksum : %d\n",ntohs(tcp->th_sum));	
		printf("  Urgent pointer : %04x\n",(tcp->th_urp));	
	}
	else if(verbose == 2){
		printf("flag : %d\n",ntohs(tcp->th_flags));
	}
	else{
		printf("TCP, ");
	}

	int sport =ntohs(tcp->th_sport) ;
	int dport =ntohs(tcp->th_dport) ;
	offset += sizeof(*tcp);

	char * appli = "UNKNOW PROTOCOL";

	if(sport == HTTP || dport == HTTP)
		appli = "HTTP";
	else if(sport == HTTPS || dport == HTTPS)
		appli = "HTTPS";
	else if(sport == FTP_TRANS || dport == FTP_TRANS)
		appli = "FTP (transfer)";
	else if(sport == FTP_ETA || dport == FTP_ETA)
		appli = "FTP (etablished)";
	else if(sport == DNS || dport == DNS)
		appli = "DNS";	
	else if(sport == SMTP || dport == SMTP)
		appli = "SMTP";
	else if(sport == POP2|| dport == POP3)
		appli = "POP2";
	else if(sport == POP3|| dport == POP3)
		appli = "POP3";
	else if(sport == IMAP || dport == IMAP)
		appli = "IMAP (2 ou 4)";
	else if(sport == IMAPSSL || dport == IMAPSSL)
		appli = "IMAP (ssl)";
	else if(sport == SCTP || dport == SCTP)
		appli = "SCTP";
	
	if(verbose == 3 || verbose == 2){
		readApplicatif(appli,header,packet,offset,verbose);
	}
	else{
		printf("%s\n",appli);
	}
}

void readApplicatif(char * application,const struct pcap_pkthdr* header,const u_char * packet, int offset, int verbose){
	printf("\033[1;34m");	
	printf("\n------------------------ DEBUT APPLCATIF ------------------\n");
	printf("\033[00m");
	printf("%s : \n",application);
	const u_char * http = (packet + offset);
	for (int i = 0; i < header->len - offset; ++i)
	{
		printf("%c",packet[i]);
	}
	printf("\033[1;34m");	
	printf("\n------------------------ FIN APPLCATIF ------------------");
	printf("\033[00m");
	printf("\n\n");
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
	else{
		printf("\033[31m");
		printf("Message reçu à %s\n",buf );
		printf("\033[00m");
	}
}

void getHeaderLength(const struct pcap_pkthdr* header,int verbose){
	if(verbose != 1)
		printf("Taille du packet : %d\n",header->len);
}