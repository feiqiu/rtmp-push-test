#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "librtmp/rtmp.h"
#include "librtmp/log.h"
#include "rtmppush.h"

typedef struct {
    RTMP *rtmp;
    char *buf_h264;
    int   len_h264;
    char *buf_g711;
    int   len_g711;
    char  url[256];
    pthread_mutex_t lock;
} RTMPPUSHER;

static int rtmp_tryconnect(RTMPPUSHER *pusher)
{
    int ret = 0;
    if (pusher->rtmp && RTMP_IsConnected(pusher->rtmp)) {
        return 0;
    }
    pthread_mutex_lock(&pusher->lock);
    if (!pusher->rtmp) pusher->rtmp = RTMP_Alloc();
    if (!pusher->rtmp) { ret = -1; goto done; }
    RTMP_Close(pusher->rtmp);
    RTMP_Init (pusher->rtmp);
    if (!RTMP_SetupURL(pusher->rtmp, pusher->url)) {
//      printf("RTMP_SetupURL failed !\n");
        ret = -1; goto done;
    }
    RTMP_EnableWrite(pusher->rtmp); // !!important, RTMP_EnableWrite must be called before RTMP_Connect
    if (!RTMP_Connect(pusher->rtmp, NULL) || !RTMP_ConnectStream(pusher->rtmp, 0)) {
//      printf("RTMP_Connect failed !\n");
        ret = -1; goto done;
    }
done:
    if (ret != 0) usleep(1000*1000);
    pthread_mutex_unlock(&pusher->lock);
    return ret;
}

void* rtmp_push_init(char *url)
{
    RTMPPUSHER *pusher = calloc(1, sizeof(RTMPPUSHER));
    if (pusher) {
//      RTMP_LogSetLevel(RTMP_LOGDEBUG);
        pthread_mutex_init(&pusher->lock, NULL);
        strncpy(pusher->url, url, sizeof(pusher->url));
        return pusher;
    }
    return NULL;
}

void rtmp_push_exit(void *ctxt)
{
    RTMPPUSHER *pusher = (RTMPPUSHER*)ctxt;
    if (pusher && pusher->rtmp) {
        RTMP_Close(pusher->rtmp);
        RTMP_Free (pusher->rtmp);
    }
    if (pusher) {
        if (pusher->buf_h264) free(pusher->buf_h264);
        if (pusher->buf_g711) free(pusher->buf_g711);
        pthread_mutex_destroy(&pusher->lock);
        free(pusher);
    }
}

#define RTMP_HEAD_SIZE (sizeof(RTMPPacket) + RTMP_MAX_HEADER_SIZE)
static void send_sps_pps(RTMPPUSHER *pusher, uint8_t *spsbuf, int spslen, uint8_t *ppsbuf, int ppslen, uint32_t pts)
{
    char        pktbuf[RTMP_HEAD_SIZE+16+spslen+ppslen];
    RTMPPacket *packet =(RTMPPacket*)pktbuf;
    char       *body   = pktbuf + RTMP_HEAD_SIZE;
    int         i      = 0;

    memset(packet, 0, sizeof(RTMPPacket));
    body[i++] = 0x17;
    body[i++] = 0x00;
    body[i++] = 0x00;
    body[i++] = 0x00;
    body[i++] = 0x00;
    body[i++] = 0x01;
    body[i++] = spsbuf[1];
    body[i++] = spsbuf[2];
    body[i++] = spsbuf[3];
    body[i++] = 0xff;
    body[i++] = 0xe1;
    body[i++] = (spslen >> 8) & 0xff;
    body[i++] = (spslen >> 0) & 0xff;
    memcpy(body+i, spsbuf, spslen);
    i += spslen;

    body[i++] = 0x01;
    body[i++] = (ppslen >> 8) & 0xff;
    body[i++] = (ppslen >> 0) & 0xff;
    memcpy(body+i, ppsbuf, ppslen);
    i += ppslen;

    packet->m_headerType  = RTMP_PACKET_SIZE_MEDIUM;
    packet->m_body        = body;
    packet->m_nBodySize   = i;
    packet->m_packetType  = RTMP_PACKET_TYPE_VIDEO;
    packet->m_nChannel    = 0x04;
    packet->m_nTimeStamp  = pts;
    packet->m_nInfoField2 = pusher->rtmp->m_stream_id;
    pthread_mutex_lock(&pusher->lock);
    RTMP_SendPacket(pusher->rtmp, packet, TRUE);
    pthread_mutex_unlock(&pusher->lock);
}

static void send_h264_data(RTMPPUSHER *pusher, uint8_t *data, int len, int key, uint32_t pts)
{
    RTMPPacket *packet;
    char       *body  ;
    int         i = 0;

    if (pusher->len_h264 < RTMP_HEAD_SIZE + 9 + len) {
        pusher->len_h264 = RTMP_HEAD_SIZE + 9 + len;
        if (pusher->buf_h264) free(pusher->buf_h264);
        pusher->buf_h264 = malloc(pusher->len_h264);
        printf("buf_h264 reallocated !\n");
    }
    if (!pusher->buf_h264) {
        printf("pusher->buf_h264 is null !\n");
        return;
    }

    packet = (RTMPPacket*)pusher->buf_h264;
    body   = pusher->buf_h264 + RTMP_HEAD_SIZE;

    memset(packet, 0, sizeof(RTMPPacket));
    body[i++] =  key ? 0x17 : 0x27;
    body[i++] =  0x01;
    body[i++] =  0x00;
    body[i++] =  0x00;
    body[i++] =  0x00;
    body[i++] = (len >> 24) & 0xff;
    body[i++] = (len >> 16) & 0xff;
    body[i++] = (len >> 8 ) & 0xff;
    body[i++] = (len >> 0 ) & 0xff;
    memcpy(body+i, data, len);

    packet->m_headerType      = RTMP_PACKET_SIZE_MEDIUM;
    packet->m_body            = body;
    packet->m_nBodySize       = len + 9;
    packet->m_packetType      = RTMP_PACKET_TYPE_VIDEO;
    packet->m_nChannel        = 0x04;
    packet->m_nTimeStamp      = pts;
    packet->m_nInfoField2     = pusher->rtmp->m_stream_id;
    pthread_mutex_lock(&pusher->lock);
    RTMP_SendPacket(pusher->rtmp, packet, TRUE);
    pthread_mutex_unlock(&pusher->lock);
}

static int parse_h264_nalu_header(uint8_t *data, int len, int *hdrsize)
{
    int  i;
    for (i=0; i<4 && i<len && !data[i]; i++);
    if (i < 2 || i == 4 || data[i] != 0x01 || ++i >= len) {
        printf("failed to find h264 frame !\n");
        return -1;
    }
    *hdrsize = i;
    return data[i] & 0x1f;
}

void rtmp_push_h264(void *ctxt, uint8_t *data, int len, uint32_t pts)
{
    RTMPPUSHER *pusher = (RTMPPUSHER*)ctxt;
    uint8_t    *spsbuf, *ppsbuf;
    int         spslen,  ppslen;
    int         type, hdrsize, key = 0;

    if (!pusher) {
        printf("h264 pusher or rtmp is null !\n");
        return;
    }
    if (rtmp_tryconnect(pusher) != 0) {
        printf("try connect failed !\n");
        return;
    }

    type = parse_h264_nalu_header(data, len, &hdrsize);
    if (type == -1) return;
    data += hdrsize;
    len  -= hdrsize;

    if (type == 7) { // get sps
        if (len < 12) {
            printf("failed to get sps data, len = %d !\n", len);
            return;
        }
        spsbuf = data;
        spslen = 12;
        data  += 12;
        len   -= 12;

        type = parse_h264_nalu_header(data, len, &hdrsize);
        if (type == -1) return;
        data += hdrsize;
        len  -= hdrsize;

        if (type == 8) {
            if (len < 4) {
                printf("failed to get pps data, len = %d !\n", len);
                return;
            }
            ppsbuf = data;
            ppslen = 4;
            data  += 4;
            len   -= 4;
        } else {
            printf("not pps data !\n");
            return;
        }
        send_sps_pps(pusher, spsbuf, spslen, ppsbuf, ppslen, pts);

        type = parse_h264_nalu_header(data, len, &hdrsize);
        if (type == -1) return;
        data += hdrsize;
        len  -= hdrsize;
        key   = 1;
    }
    if (type == 6) {
        send_h264_data(pusher, data, len, key, pts);
    }
}

void rtmp_push_g711(void *ctxt, uint8_t *data, int len, uint32_t pts)
{
    RTMPPUSHER *pusher = (RTMPPUSHER*)ctxt;
    RTMPPacket *packet;
    char       *body  ;

    if (!pusher) {
        printf("g711 pusher or rtmp is null !\n");
        return;
    }
    if (rtmp_tryconnect(pusher) != 0) {
        printf("try connect failed !\n");
        return;
    }

    if (pusher->len_g711 < RTMP_HEAD_SIZE + 1 + len) {
        pusher->len_g711 = RTMP_HEAD_SIZE + 1 + len;
        if (pusher->buf_g711) free(pusher->buf_g711);
        pusher->buf_g711 = malloc(pusher->len_g711);
        printf("buf_g711 reallocated !\n");
    }
    if (!pusher->buf_g711) {
        printf("pusher->buf_g711 is null !\n");
        return;
    }

    packet = (RTMPPacket*)pusher->buf_g711;
    body   = pusher->buf_g711 + RTMP_HEAD_SIZE;

    memset(packet, 0, sizeof(RTMPPacket));
    body[0] = 0x76;
    memcpy(body+1, data, len);

    packet->m_headerType      = RTMP_PACKET_SIZE_MEDIUM;
    packet->m_body            = body;
    packet->m_nBodySize       = len + 1;
    packet->m_packetType      = RTMP_PACKET_TYPE_AUDIO;
    packet->m_nChannel        = 0x05;
    packet->m_nTimeStamp      = pts;
    packet->m_nInfoField2     = pusher->rtmp->m_stream_id;
    pthread_mutex_lock(&pusher->lock);
    RTMP_SendPacket(pusher->rtmp, packet, TRUE);
    pthread_mutex_unlock(&pusher->lock);
}

void rtmp_push_url(void *ctxt, char *url)
{
    RTMPPUSHER *pusher = (RTMPPUSHER*)ctxt;
    if (!pusher) return;
    pthread_mutex_lock(&pusher->lock);
    if (pusher->rtmp) RTMP_Close(pusher->rtmp);
    strncpy(pusher->url, url, sizeof(pusher->url));
    pthread_mutex_unlock(&pusher->lock);
}

