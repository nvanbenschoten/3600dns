/*
 * CS3600, Fall 2013
 * Project 2 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#ifndef __3600DNS_H__
#define __3600DNS_H__

enum RECORDS {
    RECORD_A,
    RECORD_MX,
    RECORD_NS
};

int parseInputFlags(char *flag_string, int *flag_pointer);
int parseInputServer(char *server, short *port);

#endif

