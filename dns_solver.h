#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <math.h>

#define TIME_SIZE 80
#define QNAME_INDEX 14
#define ID_INDEX 2
#define QR_INDEX 4
#define RCODE_INDEX 5
#define AN_INDEX 8
#define RELATIVE_DISTANCE_TO_ANS_TYPE 2
#define RELATIVE_DISTANCE_FROM_ANS_TYPE_TO_LENGTH 8
#define IPV6_BUFFERS_SIZE 46

typedef struct dns_message dns_message;

struct dns_message{
    char id[2];
    /*qr is 0 if query, 1 response*/
    int qr;
    /*q_type =1 if AAAA, else 0*/
    int q_type;
    char *question;
    /*a_type =1 if AAAA, else 0*/
    int a_type;
    char *answer;
    int answer_number;
};

dns_message * create_new_dns_message();
dns_message *extract_message_info(char *buffer);
int extract_question_info(dns_message *dns_message, int initial_index, unsigned char message[]);
void extract_answer_info(dns_message *dns_message, int initial_index, unsigned char message[]);
int merge_hexdicimals(int num1, int num2);
int merge_four_hexdicimals(unsigned char num1, unsigned char num2, unsigned char num3, unsigned char num4);
char *get_time();
char *add_get_time(time_t passed_time);
void logging(FILE *f, dns_message *dns_message);
void modify_rep_id(char * raw_reply, dns_message *req_dns_message);
void modify_request(char *message);
unsigned char *convert_signed_to_unsigned_char(char *raw_message);
unsigned char *convert_decimal_to_hexadecimals(int decimalNumber);
int index_of_ttl(char *raw_message);
void decrement_ttl(int remaining_life, char *raw_reply);

