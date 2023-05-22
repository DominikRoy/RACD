/*
 * Copyright (C) 2013, all rights reserved by Gregory Burd <greg@burd.me>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * version 2 (MPLv2).  If a copy of the MPL was not distributed with this file,
 * you can obtain one at: http://mozilla.org/MPL/2.0/
 *
 * NOTES:
 *    - on some platforms this will require -lrt
 */

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <sys/timeb.h>


/**
 * ts_ns()
 *
 * A 1970-01-01 epoch UTC time, 1 nanosecond (ns) resolution divide by 1B to
 * get time_t.
 */
static uint64_t ts_ns();

/**
 * ts_msc()
 *
 * A 1970-01-01 epoch UTC time, 1 microsecond (mcs) resolution divide by 1M to
 * get time_t.
 */
static uint64_t ts_mcs();

/**
 * ts_ms()
 *
 * A 1970-01-01 epoch UTC time, 1 millisecond (ms) resolution divide by 1000 to
 * get time_t.
 */
static uint64_t ts_ms();

#if defined(__i386__) || defined(__x86_64__)

/**
 * cpu_clock_ticks()
 *
 * A measure provided by Intel x86 CPUs which provides the number of cycles
 * (aka "ticks") executed as a counter using the RDTSC instruction.
 */
static inline uint64_t cpu_clock_ticks();

static inline uint64_t cpu_clock_ticks_start();

static inline uint64_t cpu_clock_ticks_end();

static inline unsigned long cpu_clock_ticks_rasp();

/**
 * cpu_clock_ticks_ns()
 *
 * An approximation of nanoseconds from CPU clock ticks.
 */
static uint64_t elapsed_cpu_clock_ticks_ns(uint64_t start);


/**
 * cpu_clock_ticks_mcs()
 *
 * An approximation of microseconds from CPU clock ticks.
 */
static uint64_t elapsed_cpu_clock_ticks_mcs(uint64_t start);


/**
 * cpu_clock_ticks_ms()
 *
 * An approximation of milliseconds from CPU clock ticks.
 */
static uint64_t elapsed_cpu_clock_ticks_ms(uint64_t start);

#endif

typedef struct {
     uint64_t then;
     uint64_t (*timestamp)(void);
} duration_t;

static inline uint64_t elapsed(duration_t *duration);


#define DURATION(name, resolution) duration_t name = \
     {ts_##resolution(), ts_ ## resolution}

#define ELAPSED_DURING(result, resolution, block)       \
     do {                                               \
          DURATION(__x, resolution);                    \
          do block while(0);                            \
          *result = elapsed(&__x);                      \
     } while(0);

#define CYCLES_DURING(result, block)                    \
     do {                                               \
         uint64_t __begin = cpu_clock_ticks_start();          \
         do block while(0);                             \
         *result = cpu_clock_ticks_end() - __begin;         \
     } while(0);


#define CYCLES_DURING_ARM(result, block)                    \
     do {                                               \
         uint32_t __begin = cpu_clock_ticks_rasp();          \
         do block while(0);                             \
         *result = cpu_clock_ticks_rasp() - __begin;         \
     } while(0);


