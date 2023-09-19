#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

/**
 * @file clock-profiling.h
 * @brief 
 * @author Dominik Roy George dominik.roy.george@sit.fraunhofer.de
 * @date
 */


/**
 * @brief The Diff Function returns the difference between the start and stop time.
 * (remark: use the value of nanoseconds from the return struct)
 * @author Dominik Roy George dominik.roy.george@sit.fraunhofer.de
 * 
 * @param start 
 * @param end 
 * @return struct timespec 
 */
struct timespec diff(struct timespec start, struct timespec end);