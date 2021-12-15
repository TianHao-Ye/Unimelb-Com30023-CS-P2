#include "cache.h"

void dns_query_service(FILE *f ,char *argv[], cache_queue *cache){
	int sockfd, newsockfd;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size;

	create_socket_to_client(&sockfd, &newsockfd);
	client_addr_size = sizeof client_addr;
	newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_size);

	while(newsockfd > 0){
		int ori_bytes_read, n;
		char *buffer;
		
		/*read client request*/
	    buffer = read_data(&newsockfd);
		ori_bytes_read = (int)(unsigned char)buffer[1] +2;

		/*extract info for logging*/
		dns_message *req_dns_message = extract_message_info(buffer);
		logging(f, req_dns_message);
		/*if non-AAAA request, modify rcode and qr, send back*/
		if(req_dns_message->q_type != 1){
			modify_request(buffer);
			n = write(newsockfd, buffer, ori_bytes_read+1);
			if (n < 0) {
				perror("write");
				exit(EXIT_FAILURE);
			}
			free(buffer);
			buffer = NULL;
		}
		/*if AAAA request, check cache*/
		else{
            /*update cache first*/
            update_cache(cache, argv);
			cache_node *rep_in_cache = is_answer_in_cache_and_not_expired(req_dns_message, cache);
			/*if in cache*/
			if(rep_in_cache){
                char *cur_time = get_time();
                char *expired_time = add_get_time((time_t)rep_in_cache->life_time);
                /*log cache operation first then ans info*/
                fprintf(f, "%s %s %s %s\n", cur_time, rep_in_cache->rep_dns_message->question, "expires at", expired_time);
                logging(f, rep_in_cache->rep_dns_message);
				/*modify rep id*/
				modify_rep_id(rep_in_cache->raw_reply, req_dns_message);
				/*send dns_reply in cache to client who request it*/
				n = write(newsockfd, rep_in_cache->raw_reply, ((int)(unsigned char)rep_in_cache->raw_reply[1])+3);
				if (n < 0) {
					perror("write");
					exit(EXIT_FAILURE);
				}
                free(expired_time);
                expired_time = NULL;
                free(cur_time);
                cur_time = NULL;
				free(buffer);
			    buffer = NULL;
			}
			/*if not in cache or ans expired*/
			else{
				/*retrive reply from upper server, extract info for logging*/
				char *raw_replied_message = query_upper_server(buffer, argv);
				dns_message *rep_dns_message = extract_message_info(raw_replied_message);
				/*send reply to client who request it*/
				n = write(newsockfd, raw_replied_message, ((int)(unsigned char)raw_replied_message[1])+3);
				if (n < 0) {
					perror("write");
					exit(EXIT_FAILURE);
				}
				
                /*if no answer, not adding to cache*/
                if(rep_dns_message->answer_number == 0){
                    free(raw_replied_message);
                    raw_replied_message = NULL;
                    free_dns_message(&rep_dns_message);
                }
                /*else, added to cache, print cache evication first then ans info*/
                else{
				    add_to_cache_queue(f, rep_dns_message, buffer, raw_replied_message, cache);
                }
                logging(f, rep_dns_message);
			}
		}
	
        free_dns_message(&req_dns_message);
        
		close(newsockfd);
	    newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
	}
	if (newsockfd < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}
    close(sockfd);
}


void update_cache(cache_queue *cache, char* argv[]){
    time_t cur_time;
    int second_passed;
    cache_node *tmp = cache->head;
    while(tmp){
        time(&cur_time);
        second_passed = cur_time - tmp->last_time;
        tmp->life_time -= second_passed;
        
        /*if not expires, updating raw reply ttl field*/
        if(tmp->life_time > 0){
            decrement_ttl(tmp->life_time, tmp->raw_reply);
        }
        tmp = tmp->next;
    }
}

void traverse_cache(cache_queue *cache){
    cache_node *tmp = cache->head;
    printf("cache: \n");
    while(tmp){
        printf("question: %s\n", tmp->rep_dns_message->question);
        printf("answer: %s\n", tmp->rep_dns_message->answer);
        printf("life: %d\n", tmp->life_time);
        tmp = tmp->next;
    }
    printf("cache size: %d\n", cache->size);
    printf("\n");
}

/*cleaning up malloc*/
void free_dns_message(dns_message **cur_dns_message){
    free((*cur_dns_message)->question);
    (*cur_dns_message)->question =NULL;
    free((*cur_dns_message)->answer);
    (*cur_dns_message)->answer =NULL;
    free(*cur_dns_message);
    *cur_dns_message = NULL;
}

void free_cache_node(cache_node **node){
    free((*node)->raw_request);
    (*node)->raw_request =NULL;
    free((*node)->raw_reply);
    (*node)->raw_reply =NULL;

    free_dns_message(&((*node)->rep_dns_message));
    free(*node);
    *node =NULL;
}

void free_cache(cache_queue **cache){
    cache_node *tmp = (*cache)->head;
    cache_node *pre;
    while(tmp){
        pre = tmp;
        tmp = tmp->next;
        free_cache_node(&pre);
    }
    free(*cache);
    *cache = NULL;
}


cache_node *is_answer_in_cache_and_not_expired(dns_message *req_dns_message, cache_queue *cache){
    cache_node *answer = NULL;
    if(cache->size == 0){
        return answer;
    }
    cache_node *tmp = cache->head;
    while(tmp){
        if(strcmp(tmp->rep_dns_message->question, req_dns_message->question) ==0 && tmp->life_time >0){
            answer = tmp;
            return answer;
        }
        tmp = tmp->next;
    }
    return answer;
}

int cache_overwritten(FILE *f, cache_queue *cache, cache_node *new_cache_node){
    char *my_time = get_time();
    /*0 for no overwritten, q for overwritten*/
    int overwritten =0;
    /*first overwrite expired one*/
    cache_node *tmp, *tmp_pre;
    /*if size 0, no overwritten happen*/
    if(cache->size ==0){
        overwritten = 0;
    }
    else if(cache->head->life_time <=0){
        overwritten = 1;
        fprintf(f, "%s %s %s %s %s\n", my_time, "replacing", cache->head->rep_dns_message->question, "by", new_cache_node->rep_dns_message->question);
        if(cache->size ==1){
            free_cache_node(&(cache->head));
            cache->head = new_cache_node;
            cache->tail = new_cache_node;
        }
        else{
            new_cache_node->next = cache->head->next;
            free_cache_node(&(cache->head));
            cache->head = new_cache_node;
        }
    }
    else if(cache->tail->life_time <=0){
        overwritten = 1;
        fprintf(f, "%s %s %s %s %s\n", my_time, "replacing", cache->tail->rep_dns_message->question, "by", new_cache_node->rep_dns_message->question);
        if(cache->size ==1){
            free_cache_node(&(cache->tail));
            cache->head = new_cache_node;
            cache->tail = new_cache_node;
        }
        else{
            tmp = cache->head;
            /*find one before tail*/
            while(tmp->next != cache->tail){
                tmp = tmp->next;
            }
            tmp->next = new_cache_node;
            free_cache_node(&(cache->tail));
            cache->tail = new_cache_node;
        }
    }
    else{
        tmp = cache->head;
        while(tmp){
            if(tmp->life_time <=0){
                overwritten = 1;
                fprintf(f, "%s %s %s %s %s\n", my_time, "replacing", tmp->rep_dns_message->question, "by", new_cache_node->rep_dns_message->question);
                tmp_pre->next = new_cache_node;
                new_cache_node->next = tmp->next;
                free_cache_node(&tmp);
            }
            tmp_pre = tmp;
            tmp = tmp->next;
        }
    }
    free(my_time);
    my_time = NULL;
    return overwritten;
}

void cache_insertion(FILE *f, cache_queue *cache, cache_node *new_cache_node){
    cache_node *tmp;
    /*not full, add to tail*/
    if(cache->size <MAX_CACHE_SIZE){
        if(cache->size ==0){
            cache->head = new_cache_node;
            cache->tail = new_cache_node;
        }
        else{
            tmp = cache->head;
            while(tmp->next){
                tmp =tmp->next;
            }
            tmp->next = new_cache_node;
            cache->tail = new_cache_node;
        }
        cache->size ++;
    }
    /*full, add to tail, discard head*/
    else{
        char *my_time = get_time();
        cache_node *tmp1 = cache->head;
        cache_node *tmp2 = cache->head;
        while(tmp1->next){
            tmp1 =tmp1->next;
        }
        tmp1->next = new_cache_node;
        cache->tail = new_cache_node;

        cache->head = tmp2->next;
        /*log cache eviction*/
        fprintf(f, "%s %s %s %s %s\n", my_time, "replacing", tmp2->rep_dns_message->question, "by", new_cache_node->rep_dns_message->question);
        free(my_time);
        my_time =NULL;
        free_cache_node(&tmp2);
    }
}

void add_to_cache_queue(FILE *f,dns_message *rep_dns_message, char *raw_request, char *raw_reply, cache_queue *cache){
    cache_node *new_cache_node = create_cache_node(rep_dns_message, raw_request, raw_reply);
    cache_node *tmp, *tmp_pre;
    int overwritten = cache_overwritten(f, cache, new_cache_node);

    if(overwritten ==0){
        cache_insertion(f, cache, new_cache_node);
    }
}

cache_queue *create_cache_queue(){
    cache_queue *new_cache_queue;
    new_cache_queue = (cache_queue *)malloc(sizeof(cache_queue));
    assert(new_cache_queue);
    new_cache_queue->head = NULL;
    new_cache_queue->tail = NULL;
    new_cache_queue->size = 0;

    return new_cache_queue;
}

cache_node *create_cache_node(dns_message *rep_dns_message, char *raw_request, char *raw_reply){
    cache_node *new_cache_node = (cache_node *)malloc(sizeof(cache_node));
    assert(new_cache_node);
    new_cache_node->raw_request = raw_request;
    new_cache_node->rep_dns_message = rep_dns_message;
    new_cache_node->raw_reply = raw_reply;
    new_cache_node->life_time = extract_record_life_time(raw_reply);
    new_cache_node->last_time = time(NULL);;
    new_cache_node->next = NULL;
    return new_cache_node;
}

int extract_record_life_time(char *raw_reply){
    int life_time;

    int ttl_index = index_of_ttl(raw_reply);
    life_time = merge_four_hexdicimals(raw_reply[ttl_index], raw_reply[ttl_index+1], raw_reply[ttl_index+2], raw_reply[ttl_index+3]);
    
    return life_time;
}


