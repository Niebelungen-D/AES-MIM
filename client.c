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
  perror(msg);
  exit(1);
}

size_t writen(int fd, char *buf, size_t size)
{
    char *p = buf;
    int ret;
    int left = size;
    while(left > 0)
    {
        if((ret = write(fd, p, left)) <= 0)
        {
            if(ret < 0 && errno == EINTR)
            {
                ret = 0;
            }
            else
                return -1;
        }
        left -= ret;
        p += ret;
    }

    return size - left;
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

  close(sockfd);
  return 0;
}