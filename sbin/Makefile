build:
	gcc tcp_client.c utils/shell.c utils/socket.c -o bin/tcp_client
	gcc sslconnect.c utils/shell.c utils/socket.c -lssl -lcrypto -o bin/sslconnect 
	gcc sctp_client.c utils/shell.c utils/socket.c -o bin/sctp_client

