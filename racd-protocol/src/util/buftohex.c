#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "util/buftohex.h"

/**
 * @file buftohex.c
 * @brief  This file implements the function of the header @file buftohex.h
 * @author Dominik Roy George dominik.roy.george@sit.fraunhaufer.de
 */

char * buftohex (size_t len, unsigned char * inputbuffer){
    char * hexstring = malloc(2*len+1);


    /*Convert the digest to hex string*/    
    for(size_t i=0; i < len;i++){

        snprintf(&(hexstring[i*2]),2*len, "%02x",inputbuffer[i]);
    }

    return hexstring;
}

void charra_print_hex(const size_t buf_len, const uint8_t* const buf,
	const char* prefix, const char* postfix, const bool upper_case) {
	const char* const hex_case = upper_case ? "%02X" : "%02x";

	printf("%s", prefix);
	/* print upper case */
	for (size_t i = 0; i < buf_len; ++i) {
		printf(hex_case, buf[i]);
	}
	printf("%s", postfix);
}