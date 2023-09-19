#ifndef PPRA_NIZK_H
#define PPRA_NIZK_H
#include <sodium.h>
#include <stdbool.h>


#include "core/hash/templatehash.h"
#include "core/hash/hash_sig_verify.h"


int nizksign_eventrecord(eventrecord * rec);
bool nizkverify_eventrecord(eventrecord * rec);



#endif /* PPRA_NIZK_H */