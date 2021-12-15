#include<stdio.h>
#include<stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SELF_SERVICE_PORT "8053"
#define INITIAL_BUFFER_SIZE 2


char *query_upper_server(char *sending_message, char *argv[]);
char *read_data(int *newsockfd);
void create_socket_to_client(int *sockfd, int *newsockfd);
void create_socket_to_server(int *sockfd, char*argv[]);