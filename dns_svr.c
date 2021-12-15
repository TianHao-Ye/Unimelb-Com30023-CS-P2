#include<stdio.h>
#include<stdlib.h>

#include "cache.h"

int main(int argc, char *argv[]){
    if (argc < 3) {
		fprintf(stderr, "usage %s hostname port\n", argv[0]);
		exit(EXIT_FAILURE);
	}

    FILE *log;
    log = fopen("dns_svr.log", "a+");
    assert(log);

    cache_queue *cache = create_cache_queue();

    dns_query_service(log , argv, cache);
    
    free_cache(&cache);
    fclose(log);
    return 0;
}
