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
#include "aes.h"

#define SK_BUF_MAX 1024

const int portno = 5001;
uint8_t AES_key[0x20];

void die(const char *msg) {
  perror(msg);
  exit(1);
}

ssize_t readn(int fd, char *buf, size_t n) 
{
  size_t ret = 0;
  size_t left = n;
  char *p = buf;

  while (left > 0) {
  again:
    if ((ret = read(fd, p, left)) < 0) 
    {
      if (errno == EINTR) // interrupt
        goto again;
      else
        return -1;       // error
    } else if (ret == 0) 
      return n - left;

    left -= ret; 
    p += ret;    // mov buf pointer
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
  mpz_set_ui(ctx.g, 5); // g = 5

  // recv p
  bzero(buf, sizeof(buf));
  readn(sockfd, buf, SK_BUF_MAX);
  mpz_init_set_str(ctx.p, buf + 3, 16);
  gmp_printf("[+] p: %Zd\n\n", ctx.p);
  gmp_printf("[+] g: %Zd\n\n", ctx.g);

  // generate private key a
  generate_pri_key(ctx.pri_key);
  gmp_printf("[+] server private key(a): %Zd\n\n", ctx.pri_key);

  // A = g^a mod p
  mpz_powm(ctx.pub_key, ctx.g, ctx.pri_key, ctx.p);
  gmp_printf("[+] server public key(A): %Zd\n\n", ctx.pub_key);

  // send A
  bzero(buf, sizeof(buf));
  memcpy(buf, "pub", 3);
  mpz_get_str(buf + 3, 16, ctx.pub_key);
  writen(sockfd, buf, SK_BUF_MAX);

  // recv B
  bzero(buf, sizeof(buf));
  readn(sockfd, buf, SK_BUF_MAX);
  mpz_t B;
  mpz_init_set_str(B, buf + 3, 16);
  gmp_printf("[+] client public key(B): %Zd\n\n", B);

  // calc s
  mpz_powm(ctx.s, B, ctx.pri_key, ctx.p);
  mpz_set(s, ctx.s);
  gmp_printf("[+] share key S: %Zd\n\n", s);
}

void echo(int fd) {
  uint8_t *w; // expanded key
  int cnt = 0;
  char send_buf[SK_BUF_MAX], recv_buf[SK_BUF_MAX], text[SK_BUF_MAX];
  uint8_t msg[0x10], mac[0x10]; 

  w = AES_init(AES_key, sizeof(AES_key));
  AES_set_iv(NULL);
  memcpy(text, "msg", 3); // msg header
  bzero(msg, sizeof(msg));
  bzero(mac, sizeof(mac));
  
  while (1) {
    bzero(recv_buf, sizeof(recv_buf));
    readn(fd, recv_buf, SK_BUF_MAX);
    AES_gcm_decrypt(recv_buf, SK_BUF_MAX, recv_buf, w);
    printf("recv message:%s\n", recv_buf+3);

    if (!strncmp(recv_buf + 3, "exit", 4)) {
      break;
    }

    bzero(send_buf, sizeof(send_buf));
    AES_gcm_encrypt(recv_buf, SK_BUF_MAX, send_buf, w, msg, mac);
    writen(fd, send_buf, SK_BUF_MAX);

  }
}

int psk(int sockfd)
{
    int flag = 1; 
    unsigned char ch[SK_BUF_MAX], text[SK_BUF_MAX];
    unsigned char *w;                                   
    unsigned char key[32] = "0a12541bc5a2d6890f2536ffccab2e"; 

    bzero(ch,SK_BUF_MAX);
    gen_random_bytes(ch, 0x20); // 
    // printf("psk string:%s\n\n", ch);

    write(sockfd, ch, SK_BUF_MAX); // 
    bzero(text, SK_BUF_MAX);
    readn(sockfd, text, SK_BUF_MAX);

    w = AES_init(key, sizeof(key));
    AES_set_iv(NULL);
    AES_gcm_decrypt(text, SK_BUF_MAX, text, w);
    // printf("text: %s\n", text);
    flag = strncmp(ch, text, 0x20);

    return flag;
}

int main(int argc, char **argv) {
  int sockfd, conn_fd;
  char recv_buf[SK_BUF_MAX], send_buf[SK_BUF_MAX];
  struct sockaddr_in serv_addr;
  int n;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0) {
    die("[!] Error opening socket");
  }

  bzero((char *)&serv_addr, sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(portno);

  if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    die("[!] Error binding socket");
  }

  listen(sockfd, 5);

  conn_fd = accept(sockfd, (struct sockaddr *)NULL, NULL);

  if (conn_fd < 0) {
    die("[!] Error on accept");
  }

  int flag = psk(conn_fd);
  if (flag) {
    printf("[!] psk not pass\n");
    exit(1);
  } else
    printf("[!] psk pass\n\n");

  mpz_t s;
  mpz_init(s);
  exchange_dh_key(conn_fd, s);

  bzero(AES_key, sizeof(AES_key));
  mpz_get_str((char *)AES_key, 16, s);
  mpz_clear(s);

  echo(conn_fd);
  
  close(conn_fd);
  return 0;
}

