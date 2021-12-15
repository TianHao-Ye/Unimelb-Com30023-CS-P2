dns_svr: dns_svr.c tcp_helper.o dns_solver.o cache.o
	gcc -Wall -ansi -o dns_svr tcp_helper.o dns_solver.o cache.o dns_svr.c -lm
tcp_helper.o: tcp_helper.c
	gcc -c tcp_helper.c
dns_solver.o: dns_solver.c
	gcc -c dns_solver.c
cache.o: cache.c
	gcc -c cache.c 
clean:
	rm *.o dns_svr dns_svr.log
