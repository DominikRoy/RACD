#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <util/clock-profiling.h>

/**
 * @file clock-profiling.c
 * @brief  This file implements the function of the header @file clock-profiling.h
 * @author Dominik Roy George dominik.roy.george@sit.fraunhaufer.de
 */


struct timespec diff( struct timespec start, struct timespec end)
{
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}