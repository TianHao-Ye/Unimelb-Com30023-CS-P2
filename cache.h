#include <stdio.h>
#include <stdlib.h>
#include "dns_solver.h"
#include "tcp_helper.h"

#define CACHE
#define MAX_CACHE_SIZE 5

typedef struct cache_node cache_node;
typedef struct cache_queue cache_queue;



struct cache_node{
    dns_message *rep_dns_message;
    char *raw_request;
    char *raw_reply;
    int life_time;
    time_t last_time;
    cache_node *next;
};

struct cache_queue{
    cache_node* head;
    cache_node* tail;
    int size;
};

cache_queue *create_cache_queue();
cache_node *create_cache_node(dns_message *rep_dns_message, char *raw_request, char *raw_reply);
int extract_record_life_time(char *raw_reply);
void add_to_cache_queue(FILE *f,dns_message *rep_dns_message, char *raw_request, char *raw_reply, cache_queue *cache);

cache_node *is_answer_in_cache_and_not_expired(dns_message *req_dns_message, cache_queue *cache);

void traverse_cache(cache_queue *cache);

void update_cache(cache_queue *cache, char* argv[]);
void dns_query_service(FILE *f ,char *argv[], cache_queue *cache);

void free_dns_message(dns_message **cur_dns_message);
void free_cache(cache_queue **cache);
void free_cache_node(cache_node **node);

int cache_overwritten(FILE *f, cache_queue *cache, cache_node *new_cache_node);
void cache_insertion(FILE *f, cache_queue *cache, cache_node *new_cache_node);