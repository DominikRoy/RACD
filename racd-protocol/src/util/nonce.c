#include <sodium.h>
#include "util/nonce.h"
void generateNonce(unsigned char * buf){
    
    randombytes_buf(buf, sizeof buf);

}