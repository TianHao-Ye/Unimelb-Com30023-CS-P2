# Unimelb-Com30023-CS-P2
Simulation of DNS server.

1 Background
Note: This project will contain some reading of standards as well as writing code. If you ever write
an implementation of a protocol, you will need to read standards such as these. Therefore, becoming
familiar with the format and terminology is an important part of the field of computer systems. You will
be pointed to the relevant sections so that you do not spend your whole time reading the more arcane
parts of the text.

The Domain Name System (DNS) provides, among other things, the mapping between human-meaningful
hostnames like lms.unimelb.edu.au and the numeric IP addresses that indicate where packets should
be sent. DNS consists of a hierarchy of servers, each knowing a portion of the complete mapping.
In this project, you will write a DNS server that accepts requests for IPv6 addresses and serves them
either from its own cache or by querying servers higher up the hierarchy. Each transaction consists of at
most four messages: one from your client to you, one from you to your upstream server, one from your
upstream server to you and one from you to your client. The middle two can be sometimes skipped if
you cache some of the answers.

The format for DNS request and response messages are described in [1].
In a DNS system, the entry mapping a name to an IPv6 address is called a AAAA (or “quad A”) record
[2]. Its “record type” is 28 (QType in [2]).

The server will also keep a log of its activities. This is important for reasons such as detecting denial-ofservice
attacks, as well as allowing service upgrades to reflect usage patterns.
For the log, you will need to print a text version of the IPv6 addresses. IPv6 addresses are 128 bits long.
They are represented in text as eight colon-separated strings of 16-bit numbers expressed in hexadecimal.
As a shorthand, a string of consecutive 16-bit numbers that are all zero may be replaced by a single “::”.
Details are in [3].

2 Project specification
Task: Write a miniature DNS server that will serve AAAA queries.
This project has three variants, with increasing levels of difficulty. It is not expected that most students
will complete all tasks; the hard ones are to challenge those few who want to be challenged.
It is expected that about half the class will complete the Standard option (and do it well – you can get
an H1 by getting full marks on this), a third to complete the Cache option, and a sixth to complete
the Non-blocking option. If you think the project is taking too much time, make sure you are doing the
Standard option.
You should create a Makefile that produces an executable named ’dns_svr’.
Submission will be through git and LMS, like the first project.

2.1 Standard option
Accept a DNS “AAAA” query over TCP on port 8053. Forward it to a server whose IPv4 address is
the first command-line argument and whose port is the second command-line argument. (For testing,
use the value in /etc/resolv.conf on your server and port 53). Send the response back to the client
who sent the request, over the same TCP connection. There will be a separate TCP connection for each
query/response with the client. Log these events, as described below.
Note that DNS usually uses UDP, but this project will use TCP because it is a more useful skill for you
to learn. A DNS message over TCP is slightly different from that over UDP: it has a two-byte header
that specify the length (in bytes) of the message, not including the two-byte header itself [4, 5]. This
means that you know the size of the message before you read it, and can malloc() enough space for it.
Assume that there is only one question in the DNS request you receive, although the standard allows
there to be more than one. If there is more than one answer in the reply, then only log the first one,
but always reply to the client with the entire list of answers. If there is no answer in the reply, log the
request line only. If the first answer in the response is not a AAAA field, then do not print a log entry
(for any answer in the response).
The program should be ready to accept another query as soon as it has processed the previous query and
response. (If Non-blocking option is implemented, it must be ready before this too.)
Your server should not shut down by itself. SIGINT (like CTRL-C) will be used to terminate your server
between test cases.
You may notice that a port and interface which has been bound to a socket sometimes cannot be reused
until after a timeout. To make your testing and our marking easier, please override this behaviour by
placing the following lines before the bind() call:
int enable = 1;
if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
perror("setsockopt");
exit(1);
}

2.2 Cache option
As above, but cache the five (5) most recent answers to queries. Answer directly if possible, instead of
querying the server again.
Note that the ID field of the reply must be changed for each query so that the client doesn’t report an
error. The time-to-live (TTL) field of the reply must also be decremented by the amount of time which
has passed.
Note also that cache entries can expire. A cache entry should not be used once it has expired and a new
query should be sent to the recursive server.

If a new answer is received when the cache contains an expired entry, the expired entry (or another
expired entry) should be overwritten. If there is no expired entry, any cache eviction policy is allowed.
Do not cache responses that do not contain answers (i.e., the address was not found). If multiple answers
are returned, only cache the first one.
If you implementing caching, include the line “#define CACHE” in your code. Otherwise, this functionality
will not be tested/marked.

2.3 Non-blocking option
It can sometimes take a while for the server that was queried to give a response. To perform a recursive
DNS lookup, many servers may need to be contacted (when starting from an empty cache, from a root
DNS server down to an authoritative DNS server); any of them may be congested. Meanwhile, another
request may have arrived, which the server cannot respond to if it was blocked by the completion of the
first request.
This option extends both options above and mitigates this problem, by enabling the processing of new
requests while waiting for prior requests to complete.
This may be done using multi-threading, or select(3)/epoll(7). Using multithreading may require
explicit locking of shared resources, such as the cache, whereas a single threaded implementation using
select() will not require that. However, using select() may require significant refactoring if it is not
considered in the initial code design.
If you choose this option, you are expected to read further about multi-threading and/or select() on
your own (extending from week 3 and 10 practicals). This is training for what computer professionals
are expected to do.

Please use only a single process; do not use fork() or other means to create additional processes.
Remember that this is an advanced option; you are able to get 90% without doing it. Your time is
probably better spent ensuring you did well on the other parts. However, if you are realistically aiming
for 15/15, then this option is for you.
If you implement non-blocking, include the line “#define NONBLOCKING” in your code. Otherwise, this
functionality will not be tested/marked.
