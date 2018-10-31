#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int create_socket(char * host,int port) {
  /* returns a valid socket fd */
  int socketfd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(host);
  server.sin_port = htons(port);
  int connection_status = connect(socketfd,(struct sockaddr *)&server,sizeof(server));
  if(connection_status != 0){
    printf("Error to Connect");
    exit(1);
    return -1;
  }
  return socketfd;
}









