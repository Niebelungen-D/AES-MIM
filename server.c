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

const int portno = 5001;

void die(const char *msg) {
  die(msg);
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

  conn_fd = accept(sockfd, (struct sockaddr*)NULL, NULL);

  if (conn_fd < 0) {
    die("[!] Error on accept");
  }

  // recv/send data
  close(conn_fd);
  return 0;
}