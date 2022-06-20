#include "DH.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <gmp.h>

#define SK_BUF_MAX 1024

void die(const char *msg) {
  perror(msg);
  exit(1);
}

ssize_t readn(int fd, char *buf, size_t n) // 从fd读取n个字节数据到buf
{
  size_t ret = 0;
  size_t left = n;
  char *p = buf;

  while (left > 0) {
  again:
    if ((ret = read(fd, p, left)) < 0) // 从缓冲区读剩下的字节数
    {
      if (errno == EINTR) // 遇到中断需要再次读取
        goto again;
      else
        return -1;       // 出错了
    } else if (ret == 0) // 后续没有数据了，返回已读取的字节数
      return n - left;

    left -= ret; // 剩余字节数减去读到的字节数
    p += ret;    // 移动buf的指针
  }
  return n - left;
}

ssize_t writen(int fd, char *buf, size_t size) {
  char *p = buf;
  int ret;
  size_t left = size;
  while (left > 0) {
    if ((ret = write(fd, p, left)) <= 0) {
      if (ret < 0 && errno == EINTR) {
        ret = 0;
      } else
        return -1;
    }
    left -= ret;
    p += ret;
  }

  return size - left;
}


void exchange_dh_key(int sockfd, mpz_t s) {
  struct DH_ctx ctx; // key manager
  char buf[SK_BUF_MAX];

  // init ctx
  mpz_inits(ctx.p, ctx.g, ctx.pri_key, ctx.pub_key, ctx.s, NULL);

  // send p
  generate_p(ctx.p);
  mpz_set_ui(ctx.g, 5); // g = 5

  bzero(buf, sizeof(buf));
  memcpy(buf, "pri", 3);
  mpz_get_str(buf + 3, 16, ctx.p);
  writen(sockfd, buf, SK_BUF_MAX);
  gmp_printf("[+] p: %Zd\n\n", ctx.p);
  gmp_printf("[+] g: %Zd\n\n", ctx.g);

  // generate private key a
  generate_pri_key(ctx.pri_key);
  gmp_printf("[+] client private key(a): %Zd\n\n", ctx.pri_key);

  // A = g^a mod p
  mpz_powm(ctx.pub_key, ctx.g, ctx.pri_key, ctx.p);
  gmp_printf("[+] client public key(A): %Zd\n\n", ctx.pub_key);

  // recv B = g^b mod p
  bzero(buf, sizeof(buf));
  readn(sockfd, buf, SK_BUF_MAX);
  mpz_t B;
  mpz_init_set_str(B, buf + 3, 16);
  gmp_printf("[+] server public key(B): %Zd\n\n", B);

  // send A
  bzero(buf, sizeof(buf));
  memcpy(buf, "pub", 3);
  mpz_get_str(buf + 3, 16, ctx.pub_key);
  writen(sockfd, buf, SK_BUF_MAX);

  // calc s
  mpz_powm(ctx.s, B, ctx.pri_key, ctx.p);
  mpz_set(s, ctx.s);
  gmp_printf("[+] share key S: %Zd\n\n", s);
}

int main(int argc, char *argv[]) {
  int sockfd = 0, n = 0;
  char recv_buf[SK_BUF_MAX];
  struct sockaddr_in serv_addr;

  if (argc != 3) {
    printf("Usage: %s <ip> <port>\n", argv[0]);
    exit(1);
  }

  memset(recv_buf, 0, sizeof(recv_buf));
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    die("[!] Could not create socket \n");
  }

  memset(&serv_addr, 0, sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(atoi(argv[2]));

  if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
    die("[!] inet_pton error occured\n");
  }

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    die("[!] Connect Failed \n");
  }
  printf("[+] Server Connected\n");

  // recv/send data
  printf("[*] Now exchange key\n");
  mpz_t s;
  mpz_init(s);
  exchange_dh_key(sockfd, s);
  close(sockfd);
  return 0;
}