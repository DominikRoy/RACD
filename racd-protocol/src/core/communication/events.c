#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <unistd.h>
#include <sodium.h>

#include "core/communication/events.h"
#include "util/cbor_help.h"
#include "util/fileIO.h"

uint8_t *events_encode(events *eventlist, uint32_t *buf_len)
{
    UsefulBuf buf;
    buf.len = get_size_of_events(eventlist);
    buf.ptr = malloc(buf.len);
    //printf("%d\n", buf.len);
    QCBOREncodeContext eCtx;
    QCBOREncode_Init(&eCtx, buf);
    QCBOREncode_OpenArray(&eCtx);
    for (uint64_t i = 0; i < eventlist->count; i++)
    {

        QCBOREncode_OpenArray(&eCtx);
        QCBOREncode_AddSZString(&eCtx, eventlist->e[i].file_name);
        QCBOREncode_AddSZString(&eCtx, eventlist->e[i].file_path);
        QCBOREncode_AddBytes(&eCtx, (UsefulBufC){eventlist->e[i].file_hash, eventlist->e[i].file_hash == NULL ? 0 : TPM2_SHA256_DIGEST_SIZE});
        // for (int j = 0; j < 32; j++)
        // {
        //     printf("%02x", eventlist->e[i].file_hash[j]);
        // }
        QCBOREncode_CloseArray(&eCtx);
    }
    QCBOREncode_CloseArray(&eCtx);
    UsefulBufC Encoded;

    QCBORError uErr;
    uErr = QCBOREncode_Finish(&eCtx, &Encoded);
    //printf("\n%d\n", Encoded.len);
    //printf("\n%u\n", uErr);
    if (uErr != QCBOR_SUCCESS)
    {
        printf("event: %u\n", uErr);
    }

    uint8_t *reBuf = memcpy(malloc(Encoded.len), Encoded.ptr, Encoded.len);
    *buf_len = Encoded.len;
    free(buf.ptr);
    return reBuf;
}

int events_decode(events *eventlist, uint8_t *buf, uint64_t buf_len)
{

    QCBORDecodeContext DCtx;
    UsefulBufC bufC;
    QCBORItem item;
    bufC.len = buf_len;
    bufC.ptr = buf;
    QCBORDecode_Init(&DCtx, bufC, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_GetNext(&DCtx, &item);

    if (item.uDataType == QCBOR_TYPE_ARRAY)
    {
        eventlist->count = item.val.uCount;
        eventlist->e = calloc(eventlist->count, sizeof(event));
        for (uint8_t i = 0; i < eventlist->count; i++)
        {
            QCBORDecode_GetNext(&DCtx, &item);
            // event ev = malloc(sizeof (event));
            // memset(ev, 0, sizeof (event));
            // eventlist->e[i] = ev;
            if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 3)
            {

                QCBORDecode_GetNext(&DCtx, &item);

                if (item.uDataType == QCBOR_TYPE_TEXT_STRING)
                {
                    eventlist->e[i].file_name = memcpy(malloc(item.val.string.len + 1), item.val.string.ptr, item.val.string.len);
                    eventlist->e[i].file_name[item.val.string.len] = '\0';
                    eventlist->e[i].file_name_len = item.val.string.len;
                }

                QCBORDecode_GetNext(&DCtx, &item);

                if (item.uDataType == QCBOR_TYPE_TEXT_STRING)
                {
                    eventlist->e[i].file_path = memcpy(malloc(item.val.string.len + 1), item.val.string.ptr, item.val.string.len);
                    eventlist->e[i].file_path[item.val.string.len] = '\0';
                    eventlist->e[i].file_path_len = item.val.string.len;
                }

                QCBORDecode_GetNext(&DCtx, &item);

                if (item.uDataType == QCBOR_TYPE_BYTE_STRING && TPM2_SHA256_DIGEST_SIZE == item.val.string.len)
                {
                    eventlist->e[i].file_hash = memcpy(malloc(item.val.string.len), item.val.string.ptr, item.val.string.len);
                }
            }
        }
    }

    QCBORError uErr;
    uErr = QCBORDecode_Finish(&DCtx);
    
    if (uErr != QCBOR_SUCCESS)
    {
        printf("event: %u\n", uErr);
    }
    

    return 1;
}

size_t get_size_of_event(event event)
{
    size_t size = 1;
    size += get_size_for_cbor_string(event.file_name);
    size += get_size_for_cbor_string(event.file_path);
    size += TPM2_SHA256_DIGEST_SIZE;
    return size;
}

size_t get_size_of_events(events *eventlist)
{
    size_t size = 1; //array 2;
    size += get_size_for_cbor_uint(eventlist->count);
    for (uint8_t i = 0; i < eventlist->count; i++)
    {
        size += 1;
        size += get_size_for_cbor_string(eventlist->e[i].file_name);
        size += get_size_for_cbor_string(eventlist->e[i].file_path);
        if (eventlist->e[i].file_hash != NULL)
        {
            size += get_size_for_cbor_bstring(TPM2_SHA256_DIGEST_SIZE);
            //size += TPM2_SHA256_DIGEST_SIZE;
        }
        else
        {
            size += get_size_for_cbor_uint(0); // null filehash
        }
    }
    return size;
}

void free_events(events *eventlist)
{
    for (uint8_t i = 0; i < eventlist->count; i++)
    {

        if (eventlist->e[i].file_name_len>0)
        {
            free(eventlist->e[i].file_name);
            free(eventlist->e[i].file_path);
        }
            if (eventlist->e[i].file_hash != NULL)
            free(eventlist->e[i].file_hash);
        
    }
    free(eventlist->e);
}