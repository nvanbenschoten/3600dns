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
	  	return -1;
	}
 
    // Get flags if available
    int server_index = 1;
    int name_index = 2;
    int record_flag = RECORD_A; 

    if (argc > 3) {
        //Sets the argument indices if input has flags
        server_index++;
        name_index++;

        if(parseInputFlags(argv[1], &record_flag)) {
            printf("Error\tParsing input flags\n");
            return -1;
        }
    }

    // Allocates memory for the server char array
    char *server = (char *)calloc(strlen(argv[server_index]), sizeof(char));
	assert(server != NULL);

	// Default port number
	short port = 53;

	if(parseInputServer(server, &port)) {
		printf("Error\tParsing input server\n");
	  	free(server);
        return -1;
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
    assert(question != NULL);
    unsigned int question_len = len+6;
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
		    printf("Error\tInvalid input flag\n");
	  	    free(question);
            free(server);
            return -1;
    }
    // set QCLASS
    question[len+4] = 0x0;
    question[len+5] = 0x1;

    // merge question and header into one
    int packet_length = 12+len+6;
    unsigned char * packet = (unsigned char *)calloc(packet_length, sizeof(unsigned char));
    assert(packet != NULL);
    
    memcpy(packet, header, 12);
    memcpy(packet+12, question, len+6);

    // send the DNS request (and call dump_packet with your request)
    dump_packet(packet, packet_length);

    /* Send packet */

	// first, open a UDP socket  
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	// next, construct the destination address
	struct sockaddr_in out;
	out.sin_family = AF_INET;
	out.sin_port = htons(port);
	out.sin_addr.s_addr = inet_addr(server);
	free(server);

	if (sendto(sock, packet, packet_length, 0, (struct sockaddr *) &out, sizeof(out)) < 0) {
		// an error occurred
        printf("ERROR\tSending packet failed\n");
        free(question);
        free(packet);
        return -1;
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

    // create a buffer to be used for the response
    unsigned char response[188] = {0}; // 1500 bits
    unsigned int response_len = 188;

	// wait to receive, or for a timeout
	if (select(sock + 1, &socks, NULL, NULL, &t)) {
		if (recvfrom(sock, response, response_len, 0, (struct sockaddr *) &in, &in_len) < 0) {
			// an error occured
            printf("ERROR\tProblem receiving packet\n");
            free(question);
            free(packet);
            return -1;
		}
	} else {
        printf("NORESPONSE\n");
        free(question);
        free(packet);
        return -1;
		// a timeout occurred
	}
    free(packet);

    /* parse received packet */
    // parse response header
    char * auth_str;
    unsigned short id = ntohs(*((unsigned short *)(response)));
    unsigned char qr = (*(response+2) & 0x80) >> 7;
    unsigned char opcode = (*(response+2) & 0x78) >> 3;
    unsigned char aa = (*(response+2) & 0x4) >> 2;
    unsigned char tc = (*(response+2) & 0x2) >> 1;
    unsigned char rd = *(response+2) & 0x1;
    unsigned char ra = (*(response+2) & 0x80) >> 7;
    unsigned char z  = (*(response+2) & 0x70) >> 4;
    unsigned char rcode = *(response+2) & 0xF;

    if (id != 0x539) { // if ID is not 1337
        printf("ERROR\tDNS server returned an invalid response ID.\n");
        free(question);
        return -1;
    }
    if (qr != 1) {
        printf("ERROR\tDNS server returned invalid QR.\n");
        free(question);
        return -1;
    }
    if (opcode) {
        printf("ERROR\tDNS server returned invalid OPCODE.\n");
        free(question);
        return -1;
    }
    if (aa) { // if response is authoritative
        auth_str = "auth";
    }
    else {
        auth_str = "nonauth";
    }
    if (tc) {
        printf("ERROR\tDNS server truncated message.\n");
        free(question);
        return -1;
    }
    /*if (rd != 1) { // dunno if this error is necessary
        printf("ERROR\tRecursion is not desired.\n");
    }*/
    if (!ra) {
        printf("ERROR\tDNS server recursion was not available.\n");
        free(question);
        return -1;
    }
    /*if (!z) { // this is probably not necessary
        printf("ERROR\tZ was not zero.\n");
        return -1;
    }*/
    switch (rcode) {
        case 0:
            // rcode good!
            break;
        case 1:
            printf("ERROR\tName server was unable to interpret the query.\n");
            free(question);
            return -1;
        case 2:
            printf("ERROR\tServer failure.\n");
            free(question);
            return -1;
        case 3:
            printf("NOTFOUND\n");
            free(question);
            return -1;
        case 4:
            printf("ERROR\tThe name server does not support the requested kind of query.\n");
            free(question);
            return -1;
        case 5:
            printf("ERROR\tThe name server refused to perform the specified operation.\n");
            free(question);
            return -1;
        default:
            printf("ERROR\tUnspecified RCODE error.\n");
            free(question);
            return -1;
    }

    //unsigned short qdcount = ntohs(response[2]);
    unsigned short qdcount = ntohs(*((unsigned short *)(response+4)));
    //unsigned short ancount = ntohs(response[3]);
    unsigned short ancount = ntohs(*((unsigned short *)(response+6)));
    // unsigned short nscount = ntohs(response[4]);
    // unsigned short arcount = ntohs(response[5]);
    if (qdcount != 1) { // NOT SURE IF THIS IS A NECESSARY ERROR
        printf("ERROR\tDNS server returned an invalid question count.\n");
    }

    // 253 for max length
    unsigned char * return_name = (unsigned char *)calloc(254, sizeof(unsigned char));
    assert(return_name != NULL);
    
    // check that question is the same as what we sent out
    //int i = 0;
    char q_name[254] = {0};

    int q_offset = 12;
    if(parseLabel(response, &q_offset, q_name)) {// TODO see if this call is correct
        // DO shit
    }
    if (strcmp(q_name, domain)) { // if the received name and sent name differ
        printf("ERROR\tServer returned invalid question domain.\n");
        free(question);
    }
    unsigned short qtype_r = ntohs(*((unsigned short *)(response+q_offset))); // TODO fix offset correctness
    q_offset += 2;
    switch (record_flag) {
        case RECORD_A:
            if (qtype_r != 0x0001) {
                printf("ERROR\tDNS server returned invalid question type.\n");
                free(question);
                return -1;
            }
            break;
        case RECORD_MX:
            if (qtype_r != 0x000f) {
                printf("ERROR\tDNS server returned invalid question type.\n");
                free(question);
                return -1;
            }
            break;
        case RECORD_NS:
            if (qtype_r != 0x0002) {
                printf("ERROR\tDNS server returned invalid question type.\n");
                free(question);
                return -1;
            }
            break;
        default:
		    printf("ERROR\tDNS server returned invalid question type.\n");
            free(question);
	  	    return -1;
    }

    unsigned short qclass_r = ntohs(*((unsigned short *)(response+q_offset)));
    q_offset += 2;
    if (qclass_r != 0x0001) {
        printf("ERROR\tDNS server returned invalid QCLASS.\n");
        free(question);
        return -1;
    }

    // parse answer packet
    // parseLabel takes in:
    // packet, offset, buffer
    // returns offset of type code

    char domain_name[254] = {0};
    //unsigned int type_offset;

    if (parseLabel(response, &q_offset, domain_name)) {
        // Do shit
    }
    if (strcmp(domain_name, domain)) { // if the domain name doesn't match the sent domain name
        printf("ERROR\tDNS server returned invalid answer domain name.\n");
        free(question);
        return -1;
    }

    unsigned short atype = ntohs(*((unsigned short *)(response+q_offset)));
    // check whether type is a, cname, ns, mx
    /*switch (atype) {
        case 0x0001: // A record
            break;
        case 0x0005: // CNAME record
            break;
        case 0x0002: // NS record
            break;
        case 0x000f: // MX record
            break;
        default:
            printf("ERROR\tDNS server returned invalid answer type.\n");
            free(question);
            return -1;
    }*/
    q_offset += 2;
    unsigned short aclass = ntohs(*((unsigned short *)(response+q_offset)));
    if (aclass != 0x0001) {
        printf("ERROR\tDNS server returned invalid answer class.\n");
        free(question);
        return -1;
    }
    q_offset += 2;
    unsigned int ttl = ntohl(*((unsigned int *)(response+q_offset)));
    q_offset += 4;
    unsigned short rdlength = ntohs(*((unsigned short *)(response+q_offset)));
    q_offset += 2;

    char ip[5] = {0};
    //char
    char cname[254] = {0};
    char ns_name[254] = {0};
    char mx_name[254] = {0};
    unsigned short mx_pref;

    switch (atype) {
        case 0x0001: // A reord
            ip[0] = *(response+q_offset);
            q_offset++;
            ip[1] = *(response+q_offset);
            q_offset++;
            ip[2] = *(response+q_offset);
            q_offset++;
            ip[3] = *(response+q_offset);
            q_offset++;
            printf("IP\t%d.%d.%d.%d\t%s\n", ip[0], ip[1], ip[2], ip[3], auth_str);
            break;
        case 0x0005: // CNAME record
            parseLabel(response, &q_offset, cname);
            printf("CNAME\t%s\t%s\n", cname, auth_str);
            break;
        case 0x0002: // NS record
            parseLabel(response, &q_offset, ns_name);
            printf("NS\t%s\t%s\n", ns_name, auth_str);
            break;
        case 0x000f: // MX record
            mx_pref = ntohs(*((unsigned short *)(response+q_offset)));
            q_offset += 2;
            parseLabel(response, &q_offset, mx_name);
            printf("MX\t%s\t%d\t%s\n", mx_name, mx_pref, auth_str);
            break;
        default:
            printf("ERROR\tDNS server returned invalid answer type.\n");
            free(question);
            return -1;
    }
    
	// print out the result
    //printf("CNAME\t");

    // Free rest of malloced memory
    free(question);

	return 0;
}

/* Helper functions */

// Parses the command line inputs, taking flags into consideration
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

// Parses the server and port from the server:port string
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

// Parses a label from the packet and an offset, storing the resutls in name
int parseLabel(unsigned char *packet, int *offset, char *name) {
    while (packet[*offset] != '\0' ) {   
        // Gets the label tag 
        char tag = (packet[*offset] & 0xC0) >> 6;

        int i;
        int j;
        int label_size;
        int new_offset;

        switch (tag) {
            case 0:
                // Normal tag
                label_size = packet[*offset];
                
                // Put . in name
                for (j = 0; name[j] != '\0'; j++) {}

                name[j] = '.';
                name[j + 1] = '\0'; 
                
                // Get characters
                for (i = 1; i <= label_size; i++) {
                    char a = packet[*offset + i];

                    // Place in name array
                    for (j = 0; name[j] != '\0'; j++) {}

                    name[j] = a;
                    name[j + 1] = '\0'; 
                }


                // Increament offset
                *offset = *offset + label_size + 1;
                break;
            case 3:
                // Pointer tag

                // Finds new location and calls parseLabel
                new_offset = (*((short *)(packet + *offset)) & 0x3fff);
                parseLabel(packet, &new_offset, name);

                // Increments offset and returns
                *offset = *offset + 2;
                return 0;

            default:
                // If this is reached, there was an error
                return -1;
        }
    }

    return 0;
}
