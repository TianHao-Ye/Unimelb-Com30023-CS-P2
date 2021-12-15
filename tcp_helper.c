#include "tcp_helper.h"


char *query_upper_server(char *sending_message, char *argv[]){
    int sockfd, n, ori_bytes_read;
	char *buffer;

	create_socket_to_server(&sockfd, argv);

    /*Send message to server*/
	int sending_message_length = (int)sending_message[1]+3;
    n = write(sockfd, sending_message, sending_message_length);
    if (n < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
	/*read message from upper server*/
	buffer = read_data(&sockfd);

	close(sockfd);
    return buffer;
}

char *read_data(int *newsockfd){
	int i;
	int ori_bytes_read, more_bytes;
	char *buffer = (char *)malloc((INITIAL_BUFFER_SIZE+1) *sizeof(char));
	assert(buffer);

	
	/*reading message from client*/
	ori_bytes_read = read(*newsockfd, buffer, INITIAL_BUFFER_SIZE);
	buffer[ori_bytes_read] = '\0';
	/*check if another reads are required*/
	int bytes_required = (int)(unsigned char)buffer[1];
	while(ori_bytes_read-2 <bytes_required){
		int bytes_remaining = bytes_required -(ori_bytes_read -2);
		char new_buffer[bytes_remaining];
		more_bytes = read(*newsockfd, new_buffer, bytes_remaining);
		buffer = (char *)realloc(buffer, (more_bytes +ori_bytes_read +1) *sizeof(char));
		for(i=0; i< more_bytes; i++){
			buffer[ori_bytes_read+i] = new_buffer[i];
		}
		ori_bytes_read +=more_bytes;
	}
	buffer[ori_bytes_read] = '\0';
	return buffer;
}

void create_socket_to_client(int *sockfd, int *newsockfd){
    int n, re, i, s;
	struct addrinfo hints, *res;

	// Create address we're going to listen on (with given port number)
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;       // IPv4
	hints.ai_socktype = SOCK_STREAM; // TCP
	hints.ai_flags = AI_PASSIVE;     // for bind, listen, accept
	// node (NULL means any interface), service (port), hints, res
	s = getaddrinfo(NULL, SELF_SERVICE_PORT, &hints, &res);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	// Create socket
	*sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (*sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	// Reuse port if possible
	re = 1;
	if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	// Bind address to the socket
	if (bind(*sockfd, res->ai_addr, res->ai_addrlen) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(res);

	// Listen on socket - means we're ready to accept connections,
	// incoming connection requests will be queued, man 3 listen
	if (listen(*sockfd, 5) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}
	
}

void create_socket_to_server(int *sockfd, char*argv[]){
	int s;
	struct addrinfo hints, *servinfo, *rp;
	// Create address
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	// Get addrinfo of server. From man page:
	// The getaddrinfo() function combines the functionality provided by the
	// gethostbyname(3) and getservbyname(3) functions into a single interface
	s = getaddrinfo(argv[1], argv[2], &hints, &servinfo);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	// Connect to first valid result
	// Why are there multiple results? see man page (search 'several reasons')
	// How to search? enter /, then text to search for, press n/N to navigate
	for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
		*sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (*sockfd == -1){
            continue;
        }
		if (connect(*sockfd, rp->ai_addr, rp->ai_addrlen) != -1){
            break; // success
        }
		close(*sockfd);
	}
	if (rp == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(servinfo);
}