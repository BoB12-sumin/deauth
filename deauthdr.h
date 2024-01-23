#ifndef RADIOTAB_H
#define RADIOTAB_H

#include <sys/types.h>

struct dot11
{
    u_int8_t it_version = 0; /* set to 0 */
    u_int8_t it_pad = 0;
    u_int16_t it_len = 8;     /* entire length */
    u_int32_t it_present = 0; /* fields present */
} __attribute__((__packed__));

#endif // RADIOTAB_H

#ifndef DEAUTH_H
#define DEAUTH_H

struct deauthframe
{
    u_int16_t subtype;
    u_int16_t dur;
    u_int8_t smac[6];
    u_int8_t dmac[6];
    u_int8_t bssid[6];
    u_int16_t flagseq;

} __attribute__((__packed__));

struct deauthbody
{
    u_int16_t fixedparam;

} __attribute__((__packed__));

struct deauthpkt
{
    dot11 radio_hdr;
    deauthframe deauth_hdr;
    deauthbody deauth_body;
} __attribute__((__packed__));

#endif // DEAUTH_H
