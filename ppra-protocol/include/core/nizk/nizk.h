#ifndef PPRA_NIZK_H
#define PPRA_NIZK_H
#include <sodium.h>
#include <stdbool.h>
/**
 * @file nizk.h
 * @author Dominik Roy George (dominik.roy.george@sit.fraunhofer.de)
 * @brief This header defines function for the core feature of the project for generating the Schnorr Signaute and verifying it.
 * In other word it generates the NIZK proof/ signs the binary with NIZK proof and the NIZK verification function.
 * @version 0.1
 * @date 2020-12-12
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "core/hash/templatehash.h"
#include "core/hash/hash_sig_verify.h"
/**
 * @brief 
 *  The function takes as a parameter a eventrecord, which contains the information of the binary to generate the template hash.
 *  Next, the function signs the template hash by generating the event hash.
 *  It returns 0 if the function failed otherwise 1.
 * @param rec 
 * @return int 
 */

int nizksign_eventrecord(eventrecord * rec);

/**
 * @brief The function verifies the eventhash with the scalars c, s containing in the eventrecord, which is given as parameter.
 * The function returns a boolean value to state if the proof of knowledge was a success/valid.
 * 
 * @param rec 
 * @return true 
 * @return false 
 */
bool nizkverify_eventrecord(eventrecord * rec);



#endif /* PPRA_NIZK_H */