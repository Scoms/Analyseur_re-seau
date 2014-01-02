#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include "reader.h"
#include "analyseur.h"

#define TRUE 1
#define FALSE 0
#define BUFFSIZE 1500
#define ARGNUM 2
#define SNAPLEN 1
#define PROMISC 0
#define TOMS 0
#define INFINITY -1


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
//Globals 
int verbose;

int main(int argc, char * argv[]){

	char * device, * errbuff;
	const char * filtre;
	int optch;
	pcap_t* listener;
	verbose = 3;

    char format[] = "i:v:f:o:";
    device = "";
 
    while ((optch = getopt(argc, argv, format)) != -1)
    switch (optch) {
        case 'i':
			device = testDevice(optarg);
            break;
        case 'o':
            printf ("Paramètre o recontré\n");
            break;
        case 'f':
            filtre = optarg;
            break;
        case 'v':
            verbose = atoi(optarg) <= 3 && atoi(optarg) >= 1 ? atoi(optarg) : 3;
            break;
    }
    //printf("fin du traitement %s %i \n",device,strcmp(device," "));
    if(strcmp(device," ") == TRUE)
    	errorQuit("veuillez définir un interface ou un fichier : ./analyseur -i <interface> || ./analyseur -f <fichier>");

	listener = pcap_open_live(device, BUFSIZ, 1, 1000, errbuff); 
	if(strcmp(filtre,"") != TRUE){
		printf("Application du filtre : %s\n",filtre);
		struct bpf_program * fp;
		bpf_u_int32 netmask;
		int optimise;

		if(pcap_compile(listener, fp, filtre, optimise,netmask) != 0){
			printf("Echec lors de la compilation du filtre\n");
		}
			if(pcap_setfilter(listener,fp) != 0)
				printf("Echec lors de l'application du filtre\n");
		
	}
	pcap_datalink(listener);
    pcap_loop(listener, 2, readPacket, NULL);
	return 0;
}

void readPacket(u_char *args, const struct pcap_pkthdr* header, const u_char *packet){
	headerDisplay(header);
	packetDisplay(packet,header->len,verbose);
	printf("\n\n");
}


void headerDisplay(const struct pcap_pkthdr* header){
	getHour(header,verbose);
	getHeaderLength(header,verbose);
}

//On test si le device demander est OK 
char * testDevice(char * device){
	char errbuff[BUFFSIZE];
	char print_list[BUFFSIZE];
	char row[100];
	char * dev;
	pcap_if_t *alldevs, *d;
	int i = 0;
	int res = pcap_findalldevs(&alldevs,errbuff);

	while(1){
		bzero(print_list,BUFFSIZE);
	    for(d=alldevs; d; d=d->next)
	    {
	    	bzero(row,100);
	    	dev = d->name;
	    	strcpy(row,dev);
	    	strcat(row,"\n");
	    	if(strcmp(dev,device) == 0){
	    		return dev;
	    	}
	    	strcat(print_list,row);
	    }
		printf("%s%s :",print_list,"Choisir device");
		fscanf(stdin, "%s", device);
	}
}

void errorQuit(char * msg){
	printf("%s\n",msg);
	exit(0);
}