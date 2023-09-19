#include <stdio.h>
#include <stdint.h>
/**
 * @file fileIO.h
 * @brief 
 * @author Dominik Roy George dominik.roy.george@sit.fraunhofer.de
 * @date
 */




/**
 * @brief  The function loads a file content with the given path into a buffer with the size of the files content.
 * 
 * 
 * 
 * @param filepath Path of the file
 * @param buffer file content
 * @return int returns 1 if success loading the file and 0 if an error appears.
 */
int loadFile(const char * filepath, char ** buffer, size_t * f_size);

/**
 * @brief Get the Buffer object
 * 
 * @return char* 
 */
char * getBuffer(void);
/**
 * @brief Frees the Buffer of the file content buffer.
 * 
 */
void freeBuffer(void);
/**
 * @brief Get the Filesize object
 * 
 * @return size_t 
 */
size_t getFilesize(void);