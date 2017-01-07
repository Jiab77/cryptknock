/*
cryptknock.c
version 1.0.2 - joewalko@gmail.com - 6/18/04

This is the cryptknock client.  It works as follows:

1. The user types 'cryptknock -t <ip address> -s <src port> -d <dst port>', and 
the program prompts for the cryptknockd password. The client sends a 
UDP packet to the specified host and port. This packet contains the 'p', 
'g', and public key values used for the Diffie-Hellman key agreement.
	
2. The server receives this packet, generates its private key based of 
the 'p' value, and generates its public key based on 'g' and the private 
key. The server then derives the shared secret (for use later). The server 
then sends its public key to the client.
	
3. The client receives the server's public key and derives the shared 
secret. Using the shared secret as the symmetric encryption key, the 
client encrypts the user's password (we use RC4), places it inside a 
UDP packet, and sends the packet to the server.
	
4. The server uses the shared secret to decrypt the password stored in 
the UDP packet. The server process compares this value to the OPEN_PASSWORD 
or CLOSE_PASSWORD strings.  If the password matches the OPEN_PASSWORD, 
the server adds an iptables allow rule for that IP address. If the 
password matches the CLOSE_PASSWORD, the server deletes	the iptables 
allow rule corresponding to the client's address.

This entire process takes 3 udp packets:
	
14:20:54.743273 IP 12.150.172.100.4500 > 12.150.172.185.9090: UDP, length: 517	(Client sends server request with DH parameters)
14:20:54.783493 IP 12.150.172.185.32884 > 12.150.172.100.4500: UDP, length: 256	(Server responds with parameters)
14:20:54.806656 IP 12.150.172.100.4500 > 12.150.172.185.9090: UDP, length: 200	(Client sends encrypted knock password to server)
	
No ports ever need to be in a listening state for this to work.
	
Compile with: gcc cryptknock.c -o cryptknock -lssl -lcrypto
This also compiles with cygwin using: gcc cryptknock.c -o cryptknock -lssl -lcrypto
*/



#define SUCCESS	0
#define ERROR	1
#define KEYBYTE	256		/* The size of a 1024-bit key */
#define CIPHER	200		/* The size of the buffer of ciphertext. Messy, but this should do for now. */
#define PASS	100		/* Plaintext password buffer size */
#define TIMEOUT     8    	/* Eight seconds until we give up on contacting the server */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>		//memset
#include <signal.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <termios.h>


/* Global Variables */
DH *dh = NULL;
char server_pub[KEYBYTE];					/* The server's public key in hex form. (No terminating NULL is sent by the server.) */
BIGNUM *shared_secret = NULL;					/* DH shared secret */


/* Function Prototypes */
int check_args(int argc, char *argv[]); 						/* Check user's input */
int read_options(int argc, char *argv[], int *, int *, char **); 			/* Read the user's options */
void read_password(char *pass); 							/* Obtain user's password */
int setup_dh(void); 									/* Create client's DH 'p', 'g', public key, and private key */
int dh_send_packet(int *src_port, int *dst_port, char *server, struct sockaddr_in *);	/* Add appropriate contents to UDP packet and send to server */
int dh_receive_packet(int); 								/* Read the server's response containing its public key */
int obtain_secret(); 									/* Derive the shared secret */
int encrypt_password(char *pass, char *ciphertext); 					/* Encrypt the user's password using the shared secret */
int send_cipher(int, char *ciphertext, struct sockaddr_in *);				/* Send the RC4 encrypted password to the server */
void usage(void);


void catch_alarm(int sig_num)
{
     printf("FAILED\n");
     printf("[=] Timed out waiting for server response.\n\n");
     exit(0);

}



int main(int argc, char *argv[])
{
	struct	sockaddr_in dst;
	int	check;
	int	sock, source_port, dest_port;
	char 	*server;
	char	password[PASS];
	char	ciphertext[CIPHER] = "";
 
	signal(SIGALRM, catch_alarm);
     

	/* Check user's input */
	check = check_args(argc, argv);
	if (check == 1) return ERROR;


	/* Process user options */
	check = read_options(argc, argv, &source_port, &dest_port, &server);
	if (check == 1)
		return ERROR;
		
	
	/* Obtain user's password */
	read_password(password);	
	
	
	/* Setup the client DH parameters */
	check = setup_dh();
	if (check == 1) return ERROR;


	/* Build initial knock request */
	sock = dh_send_packet(&source_port, &dest_port, server, &dst);
	if (sock == 1) return ERROR;


	/* Read the server's response */
	check = dh_receive_packet(sock);
	if (check == 1) return ERROR;


	/* Derive the shared secret */
	check = obtain_secret();
	if (check == 1) return ERROR;


	/* Encrypt the user's password */
	check = encrypt_password(password, ciphertext);
	if (check == 1) return ERROR;


	/* Send the encrypted password to the server */
	check = send_cipher(sock, ciphertext, &dst);
	if (check == 1) return ERROR;

	
	#ifdef DEBUG2	
	printf("\nRead the password: %s\n", password);
	perror("Status of perror");
	#endif
	
	return SUCCESS;
}


void usage(void)
{

	printf("\n\tCryptknock Options:\n\n");
	printf("\t-t\tTarget server IP address\n");
	printf("\t-s\tSource port of outgoing UDP packet\n");
	printf("\t-d\tDestination port of outgoing UDP packet\n");
	printf("\n\tExample: cryptknock -t www.server.com -s 4500 -d 22796\n\n");
	exit(0);
}




int read_options(int argc, char *argv[], int *source_port, int *dest_port, char **server)
{
	int i,loop=4;

	while(loop--)
	{
		i = getopt_long(argc, argv, "t:s:d:", NULL, NULL);

		switch(i)
		{
			case 't':	
			*server = optarg;
			break;

			case 's':
			*source_port = atoi(optarg);
			break;
			
			case 'd':
			*dest_port = atoi(optarg);
			break;
			
			case '?':
			usage();	
		}
	}
	#ifdef DEBUG
	printf("[=] Cryptknocking against %s...\n", *server);
	#endif
	return SUCCESS;	
}









int send_cipher(int sockfd, char ciphertext[CIPHER], struct sockaddr_in *dst)
{

	int chars_sent;
     	printf("[=] Sending encrypted knock password to server.\n");
	chars_sent = sendto(sockfd, ciphertext, CIPHER, 0, (struct  sockaddr *) dst, sizeof(*dst));

	if (chars_sent != -1) 
	{ printf("[=] Depending on your password, your ports should be open or closed now.\n\n"); }

	#ifdef DEBUG
	printf("Number of encrypted text characters sent: %d\n", chars_sent);
	#endif

	return SUCCESS;
}








int encrypt_password(char *pass, char ciphertext[CIPHER])
{
	unsigned char *key;
	EVP_CIPHER_CTX ctx;
	int outlen;
	
	/* 
	Change the shared secret from a bignum into a hex string for use 
	as our key.  It may be possible to use the secret as-is, but I've generally
	found it easier to work with character strings than bignums.
	*/
	key = BN_bn2hex(shared_secret);
	

	/* Initialize CTX structure */
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, EVP_rc4(), NULL, key, NULL);
	
	
	/* 
	Perform the encryption using our shared DH key.
	We're using RC4, but this can be changed if wished. 
	*/
	if(!EVP_EncryptUpdate(&ctx, ciphertext, &outlen, pass, PASS))
	{
		/* Error */
		return 0;
	}


	#ifdef DEBUG2
	printf("\nEVP_EncryptUpdate() encrypted %d bytes.\n", outlen);
	printf("The user password contains %d characters\n", strlen(pass));
	#endif

	
	/* Perform cleanup */
	EVP_CIPHER_CTX_cleanup(&ctx);


	#ifdef DEBUG2
	printf("The encrypted text we are sending is: %s\n", ciphertext);	
	#endif


	return SUCCESS;
}








int obtain_secret()
{
	int len;
	unsigned char *shared_space;
	BIGNUM *bignum_server_pubkey;
	
	
	/* Convert the server's pub key in hex into a bignum */
	bignum_server_pubkey = BN_new();
	BN_hex2bn(&bignum_server_pubkey, server_pub);
	
	
	/* Allocate a new BN struct for our shared secret which is computed later */
	shared_secret = BN_new();


	/* Malloc space for the shared secret */
	shared_space = malloc(DH_size(dh));


	/* Compute the shared secret. */
	len = DH_compute_key(shared_space, (BIGNUM *) bignum_server_pubkey, dh);
	
	
	/* Convert our shared secret into bignum format */
	BN_bin2bn(shared_space, len, shared_secret);
	

	#ifdef DEBUG
	printf("\nThe shared secret is:\n");
	BN_print_fp(stdout, shared_secret); printf(", size %d\n\n", len);
	#endif


	/* We have the shared secret, so we don't need the DH struct anymore */
	DH_free(dh);
	
	
	return SUCCESS;
}







int dh_receive_packet(int sockfd)
{
	int num;
	
	
	/* We are blocking in a call to recvfrom here */
     	printf("[=] Expecting server's Diffie-Hellman key: ");
     	fflush(NULL);
	alarm(TIMEOUT); /* set timeout */
	num = recvfrom(sockfd, server_pub, sizeof(server_pub), 0, NULL, NULL);
	alarm(0); /* clear timeout */
     	if (num == -1)
     	{
        	printf("FAILED\n");
          	printf("[=] Could not contact the cryptknockd server.\n");
          	exit(0);
     	}
     	else
     	{
          	printf("SUCCESS\n");
     	}

	#ifdef DEBUG2
	printf("The server sent the public key: %s\n", server_pub);
	#endif

	return SUCCESS;
}







int dh_send_packet(int *source_port, int *dest_port, char *server, struct sockaddr_in *dst)
{
	struct sockaddr_in src;
	int sockfd;
	int chars_sent;
	int client_dh = DH_size(dh);
//	int src_port = atoi(args[2]);
	int src_port = *source_port;
//	int dst_port = atoi(args[3]);
	int dst_port = *dest_port;
	char p_buff[KEYBYTE + 1];			/* 256 byte 'p' (1024-bits) and a '\0'. The '\n' is only for clarity. */
	char pub_key_buff[KEYBYTE + 1];			/* 256 byte pubkey and a '\n' */
	char g_buff[3];					/* Our 'p' and a '\n' */
	char dh_params[517];				/* (257 * 2) + 3 = 517 */
	
	
	/* For clarity's sake, place the client's DH parameters into individual buffers */
	memcpy(p_buff, BN_bn2hex(dh->p), KEYBYTE); 		p_buff[256] = '\0';
	memcpy(pub_key_buff, BN_bn2hex(dh->pub_key), KEYBYTE);	pub_key_buff[256] = '\0';
	memcpy(g_buff, BN_bn2hex(dh->g), 2); 			g_buff[2] = '\0';
	
	
	/* Then merge the buffers */
	memcpy(dh_params, p_buff, sizeof(p_buff));
	memcpy(dh_params + sizeof(p_buff), pub_key_buff, sizeof(pub_key_buff));
	memcpy(dh_params + sizeof(p_buff) + sizeof(pub_key_buff), g_buff, 3);


	/* 
		Now, the client's Diffie-Hellman request looks like:
		<-- 257 bytes for 'p' --> <-- 257 bytes for pub_key --> <-- 3 bytes for 'g' -->	
	*/


	/* Initialize local endpoint */
	bzero(&src, sizeof(src));
	src.sin_family = AF_INET;
	src.sin_addr.s_addr = htonl(INADDR_ANY);
	src.sin_port = htons(src_port);
	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		{ printf("\nError: Local socket could not be created.\n"); return ERROR; }
	if ( bind(sockfd, (struct sockaddr *) &src, sizeof(src)) == -1)
		{ printf("\nError: Could not bind local socket to address.\n");	return ERROR; }
	
		
	/* Initialize remote endpoint */
	bzero(dst, sizeof(*dst));
	dst->sin_family = AF_INET;


	dst->sin_addr.s_addr = inet_addr(server);

	dst->sin_port = htons(dst_port);
	
	
	#ifdef DEBUG2	
	printf("\nThe user parameters are:\n");
	printf("\tSrc port: %d\n", src_port);
	printf("\tDest port: %d\n", dst_port);
	printf("\tDest ip: %s\n\n", server);
	printf("Starting sendto() using Diffie-Hellman key exchange with %d bytes...\n", sizeof(dh_params));
	#endif


     	printf("[=] Sending client Diffie-Hellman parameters to server.\n");
	chars_sent = sendto(sockfd, dh_params, sizeof(dh_params), 0, (const struct sockaddr *) dst, sizeof(*dst));


	#ifdef DEBUG2
	printf("\nNumber of characters sent: %d\n", chars_sent);
	#endif

	return sockfd;
}







int setup_dh()
{
	
	int client_p, client_pub;		/* for testing only */
	unsigned char *shared_space;
	/*
	Declare and assign static 'p' values for use in each DH struct. It's safe
	to leave these as-is, but they can be changed to other values if you want.
	*/
	const char *g = "2";	
	/* This 'p' value was generated 4/12/04 using the DH_generate_parameters() function.  It is 1024-bit in length. */
	const char *p = "C9A045312EAB864BE51B293F87416419E84CFEAB4\
2E8A00F9C0D779DAFAD3648F4B57A0BF9B4BEC031\
C224340CC47EF7D5256AB6F3331C51DE4ECBDB3B5\
1B5E7B2DF098AF1EA784747D559679FBC20E7A917\
1F3A7C5E4D7D7719792DC68E46D5474849F09EA3E\
E2FF000ECB3B1A1194D62B4798DEA3CBCDEEBFD55\
306D4BADB3";


	/* Create new DH struct for the client */
	dh = DH_new();


	/* 
	This is where we manually assign our (p, g) variables, 
	so that they don't have to be re-calculated for each run of the program.
	That is, DH_generate_parameters() is the bottle neck of our Diffie-Hellman progrm.
	The prime number 'p' takes the longest to generate.
	*/	
	//dh = DH_generate_parameters(prime_len, generator, NULL, NULL);
	BN_hex2bn(&(dh->g), g);
	BN_hex2bn(&(dh->p), p);
	
	
	/* Allocate new BN structs for our shared secrets computed later */


	/* Malloc space for the shared secret */
	shared_space = malloc(DH_size(dh));

	
	/* Generate public/private key pair for the client */
	if ( (DH_generate_key(dh)) == 0)
	{
		printf("DH_generate_key() failed.\n");
		return 1;
	}


	/* For debug purposes, obtain the sizes of our variables and print them */
	#ifdef DEBUG2
	client_p		= BN_num_bits(dh->p);	
	client_pub		= BN_num_bits(dh->pub_key);
	printf("\nClient Diffie-Hellman Parameters:\n");
	printf("\tdh->p:\t\t");		BN_print_fp(stdout, dh->p); printf(", size %d\n", client_p);
	printf("\tdh->g:\t\t"); 	BN_print_fp(stdout, dh->g); printf("\n");
	printf("\tdh->priv_key:\t");	BN_print_fp(stdout, dh->priv_key); printf("\n");
	printf("\tdh->pub_key:\t");	BN_print_fp(stdout, dh->pub_key); printf(", size %d\n", client_pub);
	#endif


	return SUCCESS;
}






void read_password(char *pass)
{
	int size;
	struct termios t_old, t_new;
	
	/* Print the prompt and turn echo off */
	printf("\nEnter password: ");
	fflush(stdout);
	tcgetattr(fileno(stdin), &t_old);
	t_new = t_old;
	t_new.c_lflag &= ~ECHO;
	t_new.c_lflag &= ~ICANON;
	tcsetattr(fileno(stdin), TCSAFLUSH, &t_new);

	/* Read in the password */
	fflush(stdin);
	fgets(pass, PASS, stdin);
	//scanf("%s", pass); /* using fgets prevents segfault */

	/* Restore old termios settings */
	tcsetattr(fileno(stdin), TCSAFLUSH, &t_old);
	fflush(stdout);
	printf("\n\n");

	pass[strlen(pass)-1] = '\0';	/* NULL terminate */
}






int check_args(int argc, char *argv[])
{
	if ( argc != 7 )
	{
		printf("\n\tCryptknock Options:\n\n");
		printf("\t-t\tTarget server IP address\n");
		printf("\t-s\tSource port of outgoing UDP packet\n");
		printf("\t-d\tDestination port of outgoing UDP packet\n");
		printf("\n\tExample: cryptknock -t 192.168.0.5 -s 4500 -d 22796\n\n");
		return ERROR;
	}
	else
		return SUCCESS;
}













