/**
 * @file buftohex.h
 * @brief 
 * @author Dominik Roy George dominik.roy.george@sit.fraunhofer.de
 * @date
 */


#ifndef PPRA_BUFTOHEX_H
#define PPRA_BUFTOHEX_H
#include <stdint.h>
/**
 * @brief This function converts the byte buffer to a hex string
 * @author Dominik Roy George dominik.roy.george@sit.fraunhofer.de
 * 
 * @param len 
 * @param inputbuffer 
 * @return char* 
 */
char * buftohex (size_t len, unsigned char * inputbuffer);

/**
 * @brief 
 * @author Michael Eckel michael.eckel@sit.fraunhofer.de
 */
void charra_print_hex(const size_t buf_len, const uint8_t* const buf,
	const char* prefix, const char* postfix, const bool upper_case);

#endif /* PPRA_BUFTOHEX_H */