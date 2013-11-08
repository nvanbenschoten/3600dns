/*
 * CS3600, Fall 2013
 * Project 3 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#include <assert.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "3600dns.h"

/**
 * This function will print a hex dump of the provided packet to the screen
 * to help facilitate debugging.  In your milestone and final submission, you 
 * MUST call dump_packet() with your packet right before calling sendto().  
 * You're welcome to use it at other times to help debug, but please comment those
 * out in your submissions.
 *
 * DO NOT MODIFY THIS FUNCTION
 *
 * data - The pointer to your packet buffer
 * size - The length of your packet
 */
static void dump_packet(unsigned char *data, int size) {
	unsigned char *p = data;
	unsigned char c;
	int n;
	char bytestr[4] = {0};
	char addrstr[10] = {0};
	char hexstr[ 16*3 + 5] = {0};
	char charstr[16*1 + 5] = {0};
	for(n=1;n<=size;n++) {
		if (n%16 == 1) {
			/* store address for this line */
			snprintf(addrstr, sizeof(addrstr), "%.4x",
			   ((unsigned int)((unsigned long)p)-(unsigned int)((unsigned long)data)) );
		}
			
		c = *p;
		if (isprint(c) == 0) {
			c = '.';
		}

		/* store hex str (for left side) */
		snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
		strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

		/* store char str (for right side) */
		snprintf(bytestr, sizeof(bytestr), "%c", c);
		strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

		if(n%16 == 0) { 
			/* line completed */
			printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
			hexstr[0] = 0;
			charstr[0] = 0;
		} else if(n%8 == 0) {
			/* half line: add whitespaces */
			strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
			strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
		}
		p++; /* next byte */
	}

	if (strlen(hexstr) > 0) {
		/* print rest of buffer if not empty */
		printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
	}
}

int main(int argc, char *argv[]) {
	/**
	* I've included some basic code for opening a socket in C, sending
	* a UDP packet, and then receiving a response (or timeout).  You'll 
	* need to fill in many of the details, but this should be enough to
	* get you started.
	*/

	// process the arguments
	if (argc < 3) {
	  	printf("Error: Usage: ./3600dns [-ns|-mx] @<server:port> <name>\n");
	  	return 1;
	}

    printf("%i : %i : %i\n", (int)sizeof(void *), (int)sizeof(long), (int)sizeof(short));
 
    // Get flags if available
    int server_index = 1;
    int name_index = 2;
    int record_flag = RECORD_A; 

    if (argc > 3) {
        //Sets the argument indices if input has flags
        server_index++;
        name_index++;

        if(parseInputFlags(argv[1], &record_flag)) {
            printf("Error parsing input flags\n");
            return 1;
        }
    }

    // Allocates memory for the server char array
    char *server = (char *)calloc(strlen(argv[server_index]), sizeof(char));
	assert(server != NULL);

	// Default port number
	short port = 53;

	if(parseInputServer(server, &port)) {
		printf("Error parsing input server\n");
	  	return 1;
	}

	/* construct the DNS request */

    // DNS Packet Header
    unsigned char header[12];
    // set  ID
    header[0] = 0x05; // set first two octets to 0
    header[1] = 0x39; // and 1337 respectively

    header[2] = 0x1; // set QR, Opcode, AA, TC, and RD
    header[3] = 0x0; // set RA, Z, and RCODE
    // set QDCOUNT
    header[4] = 0x0;
    header[5] = 0x1;
    // set ANCOUNT
    header[6] = 0x0;
    header[7] = 0x0;
    // set NSCOUNT
    header[8] = 0x0;
    header[9] = 0x0;
    // set ARCOUNT
    header[10] = 0x0;
    header[11] = 0x0;

    // DNS Packet Question
    char * domain = argv[name_index];
    unsigned int len = strlen(domain);
    unsigned char *question = (unsigned char *) calloc(len+6, sizeof(unsigned char));
    // len + 6 because . = octet, so need one additional octet for first subdomain and then
    // QTYPE and QCLASS
    //unsigned int i = 0;
    unsigned int offset = 0; // index of beginning of a length octet in QNAME
    unsigned int sublen = 0;
    while (offset < len) {
        // copy name string into question
        while (domain[offset] != '.' && domain[offset] != '\0') {
            question[offset+1] = domain[offset];
            sublen++;
            offset++;
        }
        // update string length
        //question[offset-sublen] = (0xFF & sublen) >> 8;
        question[offset-sublen] = sublen;
        sublen = 0;
        // increase offset
        offset++;
    }

    // set null terminator
    question[len+1] = 0x0;

    // set QTYPE
    question[len+2] = 0x0;
    switch (record_flag) {
        case RECORD_A:
            question[len+3] = 0x1;
            break;
        case RECORD_MX:
            question[len+3] = 0xf;
            break;
        case RECORD_NS:
            question[len+3] = 0x2;
            break;
        default:         
		    printf("Error with input flags\n");
	  	    return 1;
    }
    // set QCLASS
    question[len+4] = 0x0;
    question[len+5] = 0x1;

    // merge question and header into one
    unsigned char * packet = (unsigned char *) calloc(12+len+6, sizeof(unsigned char));
    memcpy(packet, header, 12);
    memcpy(packet+12, question, len+6);

    // send the DNS request (and call dump_packet with your request)
    dump_packet(packet, 12+len+6);

	// first, open a UDP socket  
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	// next, construct the destination address
	struct sockaddr_in out;
	out.sin_family = AF_INET;
	out.sin_port = htons(port);
	out.sin_addr.s_addr = inet_addr(server);
	free(server);

	if (sendto(sock, packet, 12+len+6, 0, (struct sockaddr *) &out, sizeof(out)) < 0) {
		// an error occurred
	}

	// wait for the DNS reply (timeout: 5 seconds)
	struct sockaddr_in in;
	socklen_t in_len;

	// construct the socket set
	fd_set socks;
	FD_ZERO(&socks);
	FD_SET(sock, &socks);

	// construct the timeout
	struct timeval t;
	t.tv_sec = 5;
	t.tv_usec = 0;

	// wait to receive, or for a timeout
	if (select(sock + 1, &socks, NULL, NULL, &t)) {
		if (recvfrom(sock, packet, 12+len+5, 0, (struct sockaddr *) &in, &in_len) < 0) {
			// an error occured
		}
	} else {
		// a timeout occurred
	}

	// print out the result

    free(packet);
    free(question);

	return 0;
}

// Helper functions
int parseInputFlags(char *flag_string, int *flag_pointer) {
    // Compare wit name server flag
    if (!strcmp(flag_string, "-ns")) {
        *flag_pointer = RECORD_NS;
        return 0;
    }

    // Compare with mail server flag
    if (!strcmp(flag_string, "-mx")) {
        *flag_pointer = RECORD_MX;
        return 0;
    }

    return -1;
}

int parseInputServer(char *server, short *port) {
	// Shift server string over one byte;
	int i;

	// Deals with port being specified
	int portSpec = 0;
	int portIndex = 0;
	char *portString = (char *)calloc(strlen(server), sizeof(char));
	assert(portString != NULL);

	// Iterates up to length
	int length = strlen(server);
	for (i = 0; i < length; i++) {
		if (portSpec) {
			portString[portIndex] = server[i+1];
			portIndex++;
		}
		else {
			server[i] = server[i+1];
			if (server[i] == ':') {
				portSpec = 1;
				server[i] = '\0';
			}
		}
	}

	if (portSpec && portIndex > 1) {
		*port = (short)atoi(portString);
	}

	free(portString);
	return 0;
}
