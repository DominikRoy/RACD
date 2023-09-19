#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <sys/timeb.h>
#include <unistd.h>
//#include "duration.h"

/**
 * ts_ns()
 *
 * A 1970-01-01 epoch UTC time, 1 nanosecond (ns) resolution divide by 1B to
 * get time_t.
 */
static uint64_t ts_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000LL + (uint64_t)ts.tv_nsec;
}

/**
 * ts_msc()
 *
 * A 1970-01-01 epoch UTC time, 1 microsecond (mcs) resolution divide by 1M to
 * get time_t.
 */
static uint64_t ts_mcs()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000LL + (uint64_t)ts.tv_nsec / 1000LL;
}

/**
 * ts_ms()
 *
 * A 1970-01-01 epoch UTC time, 1 millisecond (ms) resolution divide by 1000 to
 * get time_t.
 */
static uint64_t ts_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000LL + (uint64_t)ts.tv_nsec / 1000000LL;
}
static inline unsigned long cpu_clock_ticks_rasp(){
  uint32_t val;
  //__asm__ __volatile__("mrc p15, 0, %0, c15, c12, 0" : "=r"(val));
  __asm__ __volatile__("mrc p15, 0, %0, c9, c13, 0":"=r" (val));
  return val;
}
#if defined(__i386__) || defined(__x86_64__)

/**
 * cpu_clock_ticks()
 *
 * A measure provided by Intel x86 CPUs which provides the number of cycles
 * (aka "ticks") executed as a counter using the RDTSC instruction.
 */
static inline uint64_t cpu_clock_ticks()
{
     uint32_t lo, hi;
     __asm__ __volatile__ (
          "xorl %%eax, %%eax\n"
          "cpuid\n"
          "rdtsc\n"
          : "=a" (lo), "=d" (hi)
          :
          : "%ebx", "%ecx" );
     return (uint64_t)hi << 32 | lo;
}

static inline uint64_t cpu_clock_ticks_start()
{
    uint32_t lo, hi;
    __asm__ __volatile__("CPUID\n\t"
                         "RDTSC\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         : "=r"(hi), "=r"(lo)::"%rax", "%rbx", "%rcx", "%rdx");
    return (uint64_t)hi << 32 | lo;
}

static inline uint64_t cpu_clock_ticks_end()
{
    uint32_t lo, hi;
    __asm__ __volatile__("RDTSCP\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         "CPUID\n\t"
                         : "=r"(hi), "=r"(lo)::"%rax", "%rbx", "%rcx", "%rdx");
    return (uint64_t)hi << 32 | lo;
}

/**
 * cpu_clock_ticks_ns()
 *
 * An approximation of nanoseconds from CPU clock ticks.
 */
static uint64_t elapsed_cpu_clock_ticks_ns(uint64_t start)
{
    unsigned int overhead = 10;
    uint64_t cpu_clock_ticks_per_ms = 2300000000000LL;
    return (cpu_clock_ticks() - start - overhead) * cpu_clock_ticks_per_ms;
}


/**
 * cpu_clock_ticks_mcs()
 *
 * An approximation of microseconds from CPU clock ticks.
 */
static uint64_t elapsed_cpu_clock_ticks_mcs(uint64_t start)
{
    unsigned int overhead = 10;
    uint64_t cpu_clock_ticks_per_ms = 2300000000LL;
    return (cpu_clock_ticks() - start - overhead) * cpu_clock_ticks_per_ms;
}


/**
 * cpu_clock_ticks_ms()
 *
 * An approximation of milliseconds from CPU clock ticks.
 */
static uint64_t elapsed_cpu_clock_ticks_ms(uint64_t start)
{
    unsigned int overhead = 10;
    uint64_t cpu_clock_ticks_per_ms = 2300000LL;
    return (cpu_clock_ticks() - start - overhead) * cpu_clock_ticks_per_ms;
}

#endif

typedef struct {
     uint64_t then;
     uint64_t (*timestamp)(void);
} duration_t;

static inline uint64_t elapsed(duration_t *duration)
{
     uint64_t now = duration->timestamp();
     uint64_t elapsed = now - duration->then;
     duration->then = now;
     return elapsed;
}


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


