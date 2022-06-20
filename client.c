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

#define SK_BUF_MAX 1024

void die(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(1);
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
    printf("[!] Could not create socket \n");
    exit(1);
  }

  memset(&serv_addr, 0, sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(atoi(argv[2]));

  if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
    printf("[!] inet_pton error occured\n");
    exit(1);
  }

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("[!] Connect Failed \n");
    exit(1);
  }
  printf("[+] Server Connected\n");

  // recv/send data

  return 0;
}