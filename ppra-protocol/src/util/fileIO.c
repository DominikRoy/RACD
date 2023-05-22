#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "util/fileIO.h"

/**
 * @file fileIO.c
 * @brief  This file implements the function of the header @file fileIO.h
 * @author Dominik Roy George dominik.roy.george@sit.fraunhaufer.de
 */

int  loadFile(const char* filepath, char ** buffer,size_t * f_size)
{
    char *result = NULL;
    FILE * infile;
    size_t size;
    
    
    // /* open an existing file for reading */

     //printf("before allocation :%s\n",filepath);
    infile = fopen(filepath, "rb");

    // /* quit if the file does not exist */
    if(infile == NULL)
        return 0;
    /* Get the number of bytes */
    fseek(infile, 0L, SEEK_END);
    size = ftell(infile);
    //printf("geting size\n");
    /* reset the file position indicator to 
    the beginning of the file */
    fseek(infile, 0L, SEEK_SET);	
 
    /* grab sufficient memory for the 
    buffer to hold the text */
    *buffer = (char*)malloc(size);
    result = (char*)malloc(size);	
    /* memory error */
    if(result == NULL)
         return 0;

    // /* copy all the text into the buffer */
    fread(result, sizeof(char), size, infile);
    //printf("%zu\n",size);
    memcpy(*buffer,result,size);
    fclose(infile);
    free(result);
    *f_size=size;
    
    return 1;
}

