/*
cryptknockd.c
version 1.0.2 - joewalko@gmail.com - 6/18/04

This is the server used with the cryptknockd client.
Please change the OPEN_PASSWORD and CLOSE_PASSWORD defines
to whatever you wish. Compile it like this: 

gcc cryptknockd.c -o cryptknockd -lssl -lcrypto -lpcap

Make sure you have an updated libpcap.
The server process write messages (successes and failures) to /var/log/syslog. 

*/


#define _BSD_SOURCE
#define OPEN_PASSWORD	"open_up"			/* This password will open the server's ports. Feel free to change it. */
#define CLOSE_PASSWORD	"close_em"			/* This password will close the server's ports. */
#define IPTABLES_PATH	"/usr/sbin/iptables"		/* The location of the iptables binary */
#define KEYBYTE		256				/* The size of a 1024-bit key */
#define FILTER_PART1	"udp src port "			/* Part one of pcap filter expression */
#define FILTER_PART2	" and udp dst port "		/* Part two */
#define SUCCESS		0				/* success */
#define ERROR		1				/* error */
#define CIPHER		200				/* The size of the ciphertext char buffer */
#define PASS		100				/* The size of character buffer to place our decrypted password into */


#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <syslog.h>


/* Global variables */
pcap_t *session;		/* Pcap session handle */
DH *dh = NULL;			/* Diffie-Hellman struct */
BIGNUM *shared_secret = NULL;	/* DH shared secret */
int cli_src_port;		/* Client's source port */
char *cli_addr;			/* Client's IP address */
char *server_pub;		/* This will be the server's NULL-terminated public key in hex after a call to BN_bn2hex */
char ciphertext[CIPHER] = "";	/* The encrypted password */

struct allow_list {
	char address[16];
	struct allow_list *nextPtr;
};



/* Function prototypes */
void usage(void);										/* Print program usage */
int read_options(int, char **, char **, char **, char **);					/* Process user options */
void reaper(void);										/* Signal handler for children */
void print_error(pcap_t *);									/* error handling function */
int pcap_init(char *, char *, char *);								/* initialize our pcap interface */
int dh_send_packet(void);									/* Sends server's DH parameters to client */
void dh_receive_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);	/* rec-d client the server's public key */
void receive_ciphertext(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);	/* read in encrypted password */
int decrypt_pass(char *);									/* decrypt password using the shared key */
int compare_pass(char *);									/* compare user's pass to the real pass */
void iptables_init(void);									/* Create initial iptables filtering rules */
int command_open(struct allow_list **);								/* Run the user specified open command */
int command_close(struct allow_list **);							/* Run the user specified close command */




int main(int argc, char *argv[])
{
	char *interface;
	char *source_port;
	char *dest_port;
	int action;
	char plaintext[PASS];
	pid_t pid;
	struct allow_list *startPtr = NULL;


	if (argc < 7)
	{ usage(); }


	/* Process user options */
	if ( (read_options(argc, argv, &interface, &source_port, &dest_port)) == 1)
	{ usage(); }


	#ifdef DEBUG2
	printf("int = %s\nsource = %s\ndest = %s\n", interface, source_port, dest_port);
	#endif

	/* Daemonize */
	printf("\nCryptknockd daemon started.\n\n");
	if ( (pid = fork()) != 0 )
	{	/* We are in the PARENT process */
		exit(0);
	}	
	setsid(); /* Become session leader */

	/* Register signal handler to catch child processes */
	signal(SIGCHLD, (void *) reaper);
	
	
	/* Set up initial iptables filtering rules */
	iptables_init();


	if ( (pcap_init(interface, source_port, dest_port)) == 1)
	{ printf("Exiting with an error.\n"); return ERROR; }

	
	
	/* This is the main loop of the program. The loop consists of a cyle of
	reading a client's dh parameters, sending the server's dh parameters,
	reading and checking the client's encrypted password, and taking an
	action of firewalling or un-firewalling tcp communcation on an IP by
	IP basis. */
	while(1)
	{
		/* Enter pcap loop for receiving request */
		pcap_loop(session, -1, &dh_receive_packet, NULL);
	
	
		if ( dh_send_packet() == 1)
		{ printf("Error sending packet to client.\n"); return ERROR; }
	
	
		/* Enter pcap loop for receiving encrypted password */
		pcap_loop(session, -1, &receive_ciphertext, NULL);
	
	
		/* Decrypt the password sent by the client */
		if ( decrypt_pass(plaintext) == 1)
		{ printf("Error decrypting password.\n"); return ERROR; }


		/* Compare the user-supplied password to the real password */		
		action = compare_pass(plaintext);
		if (action == 3)
			command_close(&startPtr);
		else if (action == 2)
			command_open(&startPtr);
		else
			syslog(LOG_ERR, "cryptknockd: Received bad password for IP %s.\n", cli_addr);		
	}	

	return SUCCESS;
}





void iptables_init(void)
{	

	pid_t pid;

	/* This function create an initial firewall rule set for your host.
	Below, we flush all rules, allow new outbound connections and established connections.
	Finally, we firewall ALL inbound tcp requests. These iptables commands can be changed
	to whatever you wish. */

	/* Flush all iptables rules */
	syslog(LOG_ERR, "cryptknockd: Cryptknockd starting. Flushing all iptables rules.");
	if ( (pid = fork()) == 0 )
	{	/* We are in the child process */
		execlp(IPTABLES_PATH, "iptables", "-F", NULL);
		exit(0);
	}	

	/* Allow active connections */
	if ( (pid = fork()) == 0 )
	{	/* We are in the child process */
		/* /sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT */
		execlp(IPTABLES_PATH, "iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT", NULL);
		exit(0);
	}	

	/* And allow new outbound connections */
	if ( (pid = fork()) == 0 )
	{	/* We are in the child process */
		/* /sbin/iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT */
		execlp(IPTABLES_PATH, "iptables", "-A", "OUTPUT", "-m", "state", "--state", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT", NULL);
		exit(0);
	}	

	/* Deny everything. On receiving a valid knock password, we will allow traffic to any port
	only from the IP address who sent the correct knock.	*/
	syslog(LOG_ERR, "cryptknockd: Firewalling all inbound tcp communication.");
	if ( (pid = fork()) == 0 )
	{	/* We are in the child process */
		execlp(IPTABLES_PATH, "iptables", "-A", "INPUT", "-p", "tcp", "-j", "DROP", NULL);
		exit(0);
	}


}







void reaper()
{
	int state, pid;
  	while ((pid = waitpid(-1, &state, WNOHANG | WUNTRACED)) > 0);
}







int command_open(struct allow_list **sPtr)
{
	pid_t pid;
	struct allow_list *newPtr, *previousPtr, *currentPtr;
	
	 /* This linked list maintains a list of IP addresses that already have an allow rule 
	in iptables. iptables let's you add the same rule more than one time - we
	don't want this to happen (You could forget you accidentally added one and not remove it).
	So, every time a valid open password is received this list is searched to see if 
	the IP address has been allowed already. If not, then we add it to the list.	*/
		
	newPtr = malloc(sizeof(struct allow_list));
	if (newPtr == NULL)
	{
		printf("Malloc error!\n");
		exit(0);
	}
	else
	{
		strncpy(newPtr->address, cli_addr, 16);		/* Copy the cli_addr buffer into the struct's memory */
		newPtr->nextPtr = NULL;
		previousPtr = NULL;
		currentPtr = *sPtr; 				/* Current pointer starts out at the head of the list: */
				
		while(currentPtr != NULL)
		{	
			//printf("Comparing %s to %s.\n", currentPtr->address, cli_addr);
			if (strcmp(currentPtr->address, cli_addr) == 0) 
			{			
				//printf("[=] Client address %s is already allowed.\n", currentPtr->address);
				syslog(LOG_ERR, "cryptknockd: Client address %s is already allowed.", currentPtr->address);
				free(newPtr);
				return ERROR;
			}
			previousPtr = currentPtr;		/* walk to ... */
			currentPtr = currentPtr->nextPtr;	/* ...next node */
		}	
		
		
		/* If previousPtr is NULL the new node is inserted as the first node */
		if (previousPtr == NULL)		
		{
			newPtr->nextPtr = *sPtr;	/* New node points to old first node. */
			*sPtr = newPtr;			/* Starting node is the new node. */
		}
		
		/* Else it is inserted in place... */
		else 					
		{
			previousPtr->nextPtr = newPtr;
			newPtr->nextPtr = currentPtr;
		}
		
	}
	
	/* This is just debug code to print the current linked list:
	currentPtr = *sPtr;
	printf("The list is:\n");
	while(currentPtr != NULL)
	{
		printf("%s\n", currentPtr->address);
		currentPtr = currentPtr->nextPtr;
	}
	*/
	

	/* To allow an ip address tcp access to the system, we insert into the first position
	a rule to allow only that IP address. All other communication will fall through
	to the default deny rule (the last rule) added when this program started. */	

	syslog(LOG_ERR, "cryptknockd: Will open tcp ports for IP %s.", cli_addr);
	//printf("[=] Will open tcp ports for IP %s.\n", cli_addr);	
	if ( (pid = fork()) == 0 )
	{	/* We are in the child process */
		execlp(IPTABLES_PATH, "iptables", "-I", "INPUT", "1", "-s", cli_addr, "-p", "tcp", "-j", "ACCEPT", NULL);
		exit(0);
	}

	return SUCCESS;
}







int command_close(struct allow_list **sPtr)
{
	int found = 0;
	struct allow_list *previousPtr, *currentPtr;
	pid_t pid;
	
	if (*sPtr == NULL)
	{
		//printf("*sPtr was NULL...\n");
		return ERROR; /* Just return if there are no nodes in the allow_list */
	}
		
	previousPtr = NULL;
	
	for (currentPtr = *sPtr ; currentPtr != NULL ; previousPtr = currentPtr, currentPtr = currentPtr->nextPtr)
	{
		//printf("Comparing %s to %s.\n", currentPtr->address, cli_addr);
		if (strcmp(currentPtr->address, cli_addr) == 0)		/* Found the address */
		{
			found = 1;
			if (previousPtr == NULL)
			{
				//printf("Match found in first node.\n");
				*sPtr = currentPtr->nextPtr; 		/* Found in the first node. Set *sPtr = NULL */
			}
			else
			{
				//printf("Get here?\n");
				previousPtr->nextPtr = currentPtr->nextPtr;
			}

			free(currentPtr);
			break;
		}
				
	}
	
	if (found == 1)
	{
		/* Next, to disallow an IP address inbound tcp access to the system, we simply delete the
		corresponding iptables allow rule.  Further attemps will fall through to the default
		deny rule. Note, if the rule has already been deleted, iptables produces an error. But this does
		not affect the operation of the program. */
		syslog(LOG_ERR, "cryptknockd: Firewalling all tcp ports for IP %s.\n", cli_addr);
		//printf("[=] Firewalling all tcp ports for IP %s.\n", cli_addr);
		if ( (pid = fork()) == 0 )
		{	/* We are in the child process */
			execlp(IPTABLES_PATH, "iptables", "-D", "INPUT", "-s", cli_addr, "-p", "tcp", "-j", "ACCEPT", NULL);
			exit(0);
		}
	}

	return SUCCESS;
}







int compare_pass(char *supplied_pass)
{
	/* 1 = Bad password. */
	/* 2 = Open ports. */
	/* 3 = Close ports. */
	
	int todo;

	/* 	Is pass equal to open pass?
			Yes: todo = 2
			No: continue
		Is pass equal to close pass?
			Yes: todo = 3
			No: return ERROR
	*/

	if ( (strcmp(OPEN_PASSWORD, supplied_pass)) == 0)
		{ return (todo = 2); }
	else if ( (strcmp(CLOSE_PASSWORD, supplied_pass)) == 0)
		{ return (todo = 3); }
	else
		{ return (todo = 1); }
}





int read_options(int argc, char *argv[], char **interface, char **source_port, char **dest_port)
{
	int i,loop=4;

	if ( argc != 7)
		return ERROR;

	while(loop--)
	{
		i = getopt_long(argc, argv, "i:s:d:", NULL, NULL);

		switch(i)
		{
			case 'i':	
			*interface = optarg;
			break;

			case 's':
			*source_port = optarg;
			break;
			
			case 'd':
			*dest_port = optarg;
			break;
			
			case '?':
			usage();
		}
	}
	return SUCCESS;	
}







void usage(void)
{
	printf("\n\tCryptknockd Options:\n\n");
	printf("\t -i \t Interface to watch for cryptknock clients\n");
	printf("\t -s \t Expected source port of incoming UDP packet\n");
	printf("\t -d \t Expected destination port of incoming UDP packet\n");
	printf("\n\tExample: cryptknockd -i eth0 -s 4500 -d 22796\n\n");
	exit(0);
}








int decrypt_pass(char *plaintext)
{
	EVP_CIPHER_CTX ctx;
	unsigned char *key;
	int outlen;
	
	key = BN_bn2hex(shared_secret);
	
	/* Initialize CTX structure */
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, EVP_rc4(), NULL, key, NULL);
	
	/* Perform the decryption */
	if(!EVP_DecryptUpdate(&ctx, plaintext, &outlen, ciphertext, PASS))	/* Not sure what the last arg should be here because
										we don't know the length of the pass until we decrypt it. */
	{
		/* Error */
		return 0;
	}

	#ifdef DEBUG2
	printf("The decrypted text is: %s\n", plaintext);	
	#endif

	return SUCCESS;
}







void receive_ciphertext(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	/* Structures for interpreting the UDP packet */
	const struct ether_header	*ethernet_header;
	const struct ip			*ip_header;
	const struct udphdr		*udp_header;
	const char			*payload;	
	int size_eth	= sizeof(struct ether_header);
	int size_ip	= sizeof(struct ip);
	int size_udp	= sizeof(struct udphdr);

	/* Format the packet into readable data */
	ethernet_header	= (struct ether_header *) packet;				/* Layer 2 */
	ip_header	= (struct ip *) (packet + size_eth);				/* Layer 3 */
	udp_header	= (struct udphdr *) (packet + size_eth + size_ip);		/* Layer 4 */
	payload		= (u_char *) (packet + size_eth + size_ip + size_udp);		/* Application Layer */

	/* Re-assign the client's address to the variable. This _should_ be the same as last time. But just in case  we re-assign. */
	cli_addr = inet_ntoa(ip_header->ip_src);

	/* Move the data from the packet into buffers */
	memcpy(ciphertext, payload, CIPHER);
	

	#ifdef DEBUG
	printf("Received the following ciphertext from the client %s\n", ciphertext);
	#endif
	
	pcap_breakloop(session);
}








int dh_send_packet()
{
	int sockfd, chars_sent;
	struct sockaddr_in server;	/* the server variable is our client here */
	
	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		{ printf("\nError: Local socket could not be created.\n"); return ERROR; }
	
	bzero(&server, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(cli_addr);
	server.sin_port = htons(cli_src_port);
	
	chars_sent = sendto(sockfd, server_pub, strlen(server_pub), 0, (struct  sockaddr *) &server, sizeof(server));
	
	/* We have our shared secret, so we are done with our DH struct */
	DH_free(dh);

	return SUCCESS;
}








void dh_receive_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{


	/*
	For reference, the following structs are defined in /usr/include. Make sure _BSD_SOURCE is defined
	in this program file, because we want this to be semi-portable.
	
	From /net/ethernet.h:
	struct ether_header
	{
  		u_int8_t  ether_dhost[ETH_ALEN];	// destination eth addr 
  		u_int8_t  ether_shost[ETH_ALEN];      	// source ether addr    
  		u_int16_t ether_type;                	// packet type ID field 
	} __attribute__ ((__packed__));
	
	
	From /netinet/ip.h:
	struct ip
	{
		#if __BYTE_ORDER == __LITTLE_ENDIAN
    			unsigned int ip_hl:4;		// header length 
			unsigned int ip_v:4;           	// version 
		#endif
		#if __BYTE_ORDER == __BIG_ENDIAN
    			unsigned int ip_v:4;          	// version
    			unsigned int ip_hl:4;          	// header length
		#endif
   	 	u_int8_t ip_tos;                   	// type of service
    		u_short ip_len;                    	// total length
    		u_short ip_id;                    	// identification
    		u_short ip_off;                     	// fragment offset field
		#define IP_RF 0x8000                    // reserved fragment flag
		#define IP_DF 0x4000                    // dont fragment flag
		#define IP_MF 0x2000                    // more fragments flag
		#define IP_OFFMASK 0x1fff               // mask for fragmenting bits
    		u_int8_t ip_ttl;                    	// time to live
    		u_int8_t ip_p;                      	// protocol
    		u_short ip_sum;                     	// checksum
    		struct in_addr ip_src, ip_dst;      	// source and dest address
  	};


	From /netinet/udp.h
	// UDP header as specified by RFC 768, August 1980.
	struct udphdr {
   		u_int16_t uh_sport;           		// source port
        	u_int16_t uh_dport;           		// destination port
        	u_int16_t uh_ulen;            		// udp length 
        	u_int16_t uh_sum;             		// udp checksum
	};
	*/
	
	/* DH parameters sent by client */
	char p[KEYBYTE+1];
	char client_pub_key[KEYBYTE+1];
	char g[3];		

	/* Our server's public key */
	const char server_pub_key[KEYBYTE];

	/* Structures for interpreting the UDP packet */
	const struct ether_header	*ethernet_header;
	const struct ip			*ip_header;
	const struct udphdr		*udp_header;
	const char			*payload;	
	int size_eth	= sizeof(struct ether_header);
	int size_ip	= sizeof(struct ip);
	int size_udp	= sizeof(struct udphdr);
	
	int len;
	int server_p;
	int server_pub_size;
	unsigned char *shared_space;
	BIGNUM *bignum_client_pubkey;

	/* Format the packet into readable data */
	ethernet_header	= (struct ether_header *) packet;
	ip_header	= (struct ip *) (packet + size_eth);
	udp_header	= (struct udphdr *) (packet + size_eth + size_ip);
	payload		= (u_char *) (packet + size_eth + size_ip + size_udp);

	/* Move the data from the packet into buffers */
	memcpy(p, payload, KEYBYTE + 1);
	memcpy(client_pub_key, payload + KEYBYTE + 1, KEYBYTE + 1);	/* The "+1" is used for the terminating '\0' character */  
	memcpy(g, payload + (KEYBYTE * 2) + 2, 3);			/* Skip over two 256-byte keys and 2 NULL chars to get our 'g' */


	/* Record the client's src port for use as the dst port in the reply, and its IP */
	cli_src_port = ntohs(udp_header->uh_sport);
	cli_addr = inet_ntoa(ip_header->ip_src);
	

	#ifdef DEBUG2
	printf("The client's source IP address is: %s\n", cli_addr);
	printf("The source port we received data from is: %d\n", cli_src_port);
	printf("The length of the data we received is: %d\n", ntohs(udp_header->uh_ulen));	
	printf("The client's 'p' variable is: \n%s\n", p);
	printf("The client's public key variable is: \n%s\n", client_pub_key);
	printf("The client's 'g' key variable is: \n%s\n", g);
	#endif



	/* Now, place our client's 'p' and 'g' parameters into our DH struct */
	dh		= DH_new();
	BN_hex2bn(&(dh->g), g);
	BN_hex2bn(&(dh->p), p);
	
	
	/* Move the client's public key in hex form into a bignum */
	bignum_client_pubkey = BN_new();
	BN_hex2bn(&bignum_client_pubkey, client_pub_key);

	
	/* Allocate a new BN struct for our shared secret which is computed later */
	shared_secret = BN_new();


	
	/* Malloc space for the shared secret */
	shared_space = malloc(DH_size(dh));



	/* Generate public/private key pair for the server */
	if ( (DH_generate_key(dh)) == 0)
	{
		printf("DH_generate_key() failed.\n");
		exit(0); 	/* Not sure how to return a value because we came from pcap's callback function */
	}

	
	
	/* 
	Compute the shared secret. This will be used as the symmetric key 
	to our RC4 (or you can choose another symmetric cipher) cipher. 
	Note that some people advise using a "key derivation function" to obtain another key
	instead of using the shared secret directly. Essentially, the job of a KDF is to serve as another 
	layer of abstraction to the key (to add security against mitm attacks, or format 
	it for use as another symmetric encryption key.	See the paper "Security Issues 
	in the Diffie-Hellman Key Agreement Protocol" (Raymond & Stiglic) for more information. 
	We're not using a KDF here, but the program could be modified to do so.
	*/
	len = DH_compute_key(shared_space, (BIGNUM *)bignum_client_pubkey, dh);
	
	
	/* Convert our shared secret into bignum format */
	BN_bin2bn(shared_space, len, shared_secret);



	
	/* For debug purposes, obtain the sizes of our variables and print them */
	#ifdef DEBUG2
	server_p		= BN_num_bits(dh->p);	
	server_pub_size		= BN_num_bits(dh->pub_key);
	
	printf("\nServer Diffie-Hellman Parameters:\n");
	printf("\tdh->p:\t\t");		BN_print_fp(stdout, dh->p); printf(", size %d\n", server_p);
	printf("\tdh->g:\t\t"); 	BN_print_fp(stdout, dh->g); printf("\n");
	printf("\tdh->priv_key:\t");	BN_print_fp(stdout, dh->priv_key); printf("\n");
	printf("\tdh->pub_key:\t");	BN_print_fp(stdout, dh->pub_key); printf(", size %d\n", server_pub_size);

	printf("\nThe shared secret is:\n");
	BN_print_fp(stdout, shared_secret); printf(", size %d\n\n", len);
	#endif
	

	/* Move the server's public key into a hex number for easy transmission to the client */
	server_pub = BN_bn2hex(dh->pub_key);
	pcap_breakloop(session);

}







int pcap_init(char *interface, char *source_port, char *destination_port)
{
	char *dev = interface;			/* Device we are sniffing on */
	char errbuf[PCAP_ERRBUF_SIZE];		/* Error string returned, see pcap manpage */
	struct bpf_program filter;		/* The compiled filter */
	char filter_string[200] = FILTER_PART1;
	char filter_string2[200] = FILTER_PART2;
	bpf_u_int32 mask;			/* Our netmask */
	bpf_u_int32 net;			/* Our IP */

	/* Append the user's src port parameter to the filter expression */
	strncat(filter_string, source_port, strlen(source_port));
	
	/* Append the second part of the filter expression to the first part */
	strncat(filter_string, filter_string2, strlen(filter_string2));
	
	/* Finally, append the user's dest port parameter to the end of the filter expression */
	strncat(filter_string, destination_port, strlen(destination_port));


	/* Define the pcap device */
	if ((pcap_lookupnet(dev, &net, &mask, errbuf)) < 0 )
	{
		printf("Error looking up pcap device: %s\n", errbuf);
		return ERROR;
	}
	

	/* Open the pcap session */
	if ( (session = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf)) == NULL)
	{
		printf("Error with pcap_open_live: %s\n", errbuf);
		return ERROR;
	}
	
	
	/* Compile a new filter */
	if ((pcap_compile(session, &filter, filter_string, 0, net)) < 0)
	{
		print_error(session);
		return ERROR;
	}
	
	
	/* Apply the filter */
	if (  (pcap_setfilter(session, &filter)) < 0)
	{
		print_error(session);
		return ERROR;
	}


	return SUCCESS;
}






void print_error(pcap_t *s)
{
	/* 	From the pcap manpage:
		void pcap_perror(pcap_t *p, char *prefix) */
	char *prefix = "The following pcap error occurred";
	pcap_perror(s, prefix);
}












