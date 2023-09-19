#include <stdio.h>
#include <string.h>
#include <util/fileIO.h>
#include <core/hash/templatehash.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <libgen.h>
#include <util/clock-profiling.h>
#include <tss2/tss2_tpm2_types.h>
#include <util/nonce.h>
#include <sodium.h>
#include <mbedtls/sha256.h>
#include "core/hash/hash_sig_verify.h"
#include "core/hash/templatehash.h"
#include "core/communication/attestphase.h"

#include "core/communication/events.h"
#include "util/cbor_help.h"
#include "core/dto/ppra_dto_message_encdec.h"
#include "core/tpm2_charra/charra_util.h"
#include "duration.h"
// static inline uint64_t cpu_clock_ticks_start()
// {
//     uint32_t lo, hi;
//     __asm__ __volatile__("CPUID\n\t"
//                          "RDTSC\n\t"
//                          "mov %%edx, %0\n\t"
//                          "mov %%eax, %1\n\t"
//                          : "=r"(hi), "=r"(lo)::"%rax", "%rbx", "%rcx", "%rdx");
//     return (uint64_t)hi << 32 | lo;
// }

// static inline uint64_t cpu_clock_ticks_end()
// {
//     uint32_t lo, hi;
//     __asm__ __volatile__("RDTSCP\n\t"
//                          "mov %%edx, %0\n\t"
//                          "mov %%eax, %1\n\t"
//                          "CPUID\n\t"
//                          : "=r"(hi), "=r"(lo)::"%rax", "%rbx", "%rcx", "%rdx");
//     return (uint64_t)hi << 32 | lo;
// }
// static inline unsigned long cpu_clock_ticks_rasp(){
//   uint32_t val;
//   asm volatile("mrc   p15, 0, %0, c15, c12, 0" : "=r"(val));
//   return val;
// }
int main()
{

    unsigned char nonce[crypto_box_NONCEBYTES];

    generateNonce(nonce);
    eventrecords records;
    char *buffer;
    size_t f_size;
    loadFile("/run/media/dominik/DATA/Master/Master_Dev/ppra-protocol/programs100.cbor", &buffer, &f_size);
    events evlist;
    events_decode(&evlist, buffer, f_size);
    //freeBuffer();
    free(buffer);
    records.count = evlist.count;
    records.record = calloc(evlist.count, sizeof(eventrecord));
    //printf("count :%lu\n", records.count);
    //size_t com_cost_sml =0;
    //size_t com_cost_sml_pp = 0;
    //size_t com_cost_sml_pp_2 = 0;

    for (size_t index = 0; index < records.count; index++)

    {
        records.record[index].event.e = (event *)calloc(1, sizeof(struct event));
        records.record[index].event.count = 1;

        size_t fname_len = evlist.e[index].file_name_len;
        records.record[index].event.e[0].file_name = malloc(sizeof(char) * fname_len + 1);
        memcpy(records.record[index].event.e[0].file_name, evlist.e[index].file_name, fname_len);
        records.record[index].event.e[0].file_name[fname_len] = '\0';
        records.record[index].event.e[0].file_name_len = fname_len;
       // printf("fname_len :%s\n", records.record[index].event.e[0].file_name);
        //com_cost_sml += fname_len;
        //com_cost_sml_pp += fname_len;

        size_t fpath_len = evlist.e[index].file_path_len;
        records.record[index].event.e[0].file_path = malloc(sizeof(char) * fpath_len + 1);
        memcpy(records.record[index].event.e[0].file_path, evlist.e[index].file_path, fpath_len);
        records.record[index].event.e[0].file_path[fpath_len] = '\0';
        records.record[index].event.e[0].file_path_len = fpath_len;
        //com_cost_sml += fpath_len;
        //com_cost_sml_pp += fpath_len;

        //printf("path :%s\n", records.record[index].event.e[0].file_path);

        records.record[index].event.e[0].file_hash = malloc(TPM2_SHA256_DIGEST_SIZE);
        memcpy(records.record[index].event.e[0].file_hash, evlist.e[index].file_hash, TPM2_SHA256_DIGEST_SIZE);

        //printf("%lu\n", records.record[index].event.e[0].file_path_len);
        //nizksign_eventrecord(&records.record[index]);
        //nizkverify_eventrecord(&records.record[index]);

        //com_cost_sml += TPM2_SHA256_DIGEST_SIZE;
        //com_cost_sml_pp += TPM2_SHA256_DIGEST_SIZE;

        //com_cost_sml += (TPM2_SHA256_DIGEST_SIZE + TPM2_SHA256_DIGEST_SIZE + 1);
        //com_cost_sml_pp += (TPM2_SHA256_DIGEST_SIZE+ TPM2_SHA256_DIGEST_SIZE + 1+ 96);
        //com_cost_sml_pp_2 += (TPM2_SHA256_DIGEST_SIZE+1+2);
        records.record[index].pcr = 10;

        // for (size_t i = 0; i < 32; i++)
        // {
        //     printf("%02x", records.record[index].event.e[0].file_hash[i]);
        // }
        // printf("\n\r");
        // for (size_t i = 0; i < 64; i++)
        // {
        //     printf("%02x", records.record[index].c[i]);
        // }
        // printf("\n\r");
        // for (size_t i = 0; i < 32; i++)
        // {
        //     printf("%02x", records.record[index].s[i]);
        // }
        // printf("\n\r");
    }
    //printf("SML sum :%lu\n",com_cost_sml);
    //printf("SML sum pp:%lu\n",com_cost_sml_pp);
    //printf("SML sum pp 2:%lu\n",com_cost_sml_pp_2);
    //printf("80:%f\n",(0.8)*com_cost_sml_pp_2);
     //printf("70:%f\n",(0.7)*com_cost_sml_pp_2);
     // printf("60:%f\n",(0.6)*com_cost_sml_pp_2);
   // printf("20:%f\n",(0.2)*com_cost_sml_pp);
   // printf("30:%f\n",(0.3)*com_cost_sml_pp);
   // printf("40:%f\n",(0.4)*com_cost_sml_pp);
    uint64_t results[records.count];
    uint64_t resultsver[records.count];
    // for (size_t i = 0; i < 1000; i++)
    // {
    uint64_t cyclessign;
    uint64_t cyclesverify;

    //CPU CYCLES
    // for (size_t index = 0; index < records.count; index++)

    // {
    //     CYCLES_DURING(&cyclessign, {
    //         nizksign_eventrecord(&records.record[index]);
    //     });
    //     results[index] = cyclessign;
    //     CYCLES_DURING(&cyclesverify, {
    //        //printf("%s", nizkverify_eventrecord(&records.record[index]) ? "true" : "false"); 
    //     nizkverify_eventrecord(&records.record[index]);
	// });
    //     resultsver[index] = cyclesverify;
    // }

        //CPU CYCLES ARM
    // for (size_t index = 0; index < records.count; index++)

    // {
    //     CYCLES_DURING_ARM(&cyclessign, {
    //         nizksign_eventrecord(&records.record[index]);
    //     });
    //     results[index] = cyclessign;
    //     CYCLES_DURING_ARM(&cyclesverify, {
    //        //printf("%s", nizkverify_eventrecord(&records.record[index]) ? "true" : "false"); 
    //     nizkverify_eventrecord(&records.record[index]);
	// });
    //     resultsver[index] = cyclesverify;
    // }

    //EXEC TIME in ns
    for (size_t index = 0; index < records.count; index++)

    {
        ELAPSED_DURING(&cyclessign, ns, {
            nizksign_eventrecord(&records.record[index]);
        });
        results[index] = cyclessign;
        ELAPSED_DURING(&cyclesverify, ns , {
        //printf("%s", nizkverify_eventrecord(&records.record[index]) ? "true" : "false"); 
        nizkverify_eventrecord(&records.record[index]);
	});
        resultsver[index] = cyclesverify;
    }


    //  CYCLES_DURING(&cyclessign, {for (size_t index = 0; index < records.count; index++)

    // {
       
    //     
        
        

    // }});
      //  results[0] = cyclessign;

    /* CYCLES_DURING(&cyclesverify, {or (size_t index = 0; index < records.count; index++)

    {
        nizksign_eventrecord(&records.record[index]);
         printf("%s",nizksign_eventrecord(&records.record[index]));
        
        

    }//});*/
	//resultsver[0] = cyclesverify;
    //}

    FILE *f = fopen("cycle100sign_exec.csv", "w");
    FILE *f1 = fopen("cycle100verify_exec.csv", "w");
    if (f == NULL)
        return -1;
    if (f1 == NULL)
        return -1;
    for (int i = 0; i < records.count; i++)
    {
        // you might want to check for out-of-disk-space here, too
        fprintf(f, "%lu\n", results[i]);
        fprintf(f1, "%lu\n", resultsver[i]);
    }
    fclose(f);
    fclose(f1);

    free_eventrecords(&records);
    free_events(&evlist);

    return (0);
}
