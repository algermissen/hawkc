#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ciron.h is the only header file you need to include. */
#include "hawkc.h"

#define BUF_SIZE 1024

typedef enum hmode {
	PLAIN, CURL, BLITZ, HEADER, QHEADER
} hmode_t;


void usage(void);
void help(void);

static char *GET = "GET";
static char *PORT80 = "80";

static char *mystrdup(const char *in, const char *fieldname) {
	char *p;
	if( (p = (char *)malloc(strlen(in)+1)) == NULL) {
		fprintf(stderr,"Unable to allocate for %s\n" , fieldname);
		exit(1);
	}
	strcpy(p, optarg);
	return p;
}

int main(int argc, char **argv) {

	HawkcError e;
#ifdef __cplusplus
	_HawkcContext ctx;
#else
        struct HawkcContext ctx;
#endif
	char *id = NULL;
	char *password = NULL;
	char *method = NULL;
	char *host = NULL;
	char *port = NULL;
	char *path = NULL;
	char *ext = NULL;
	hmode_t mode = PLAIN;

	HawkcAlgorithm algorithm = NULL;

	/*
	unsigned char *input;
	int input_len = 1;
	unsigned char *encryption_buffer;
	unsigned char *output_buffer;
	int encryption_buffer_len;
	int output_buffer_len;
	*/

	unsigned char *buffer;
	size_t len, required_len;


	int option;

	hawkc_context_init(&ctx);

	opterr = 0;

	while ((option = getopt(argc, argv, "-i:p:M:H:O:P:e:a:o:m:h")) != EOF) {
		switch (option) {
		case 'i': id = mystrdup(optarg,"id"); break;
		case 'p': password = mystrdup(optarg,"password"); break;
		case 'M': method = mystrdup(optarg,"method"); break;
		case 'H': host = mystrdup(optarg,"host"); break;
		case 'O': { port = mystrdup(optarg,"port");
			errno = 0;
			int p = strtol(port, (char **)NULL, 10);
			if(errno != 0) {
				perror("Port not a valid integer");
			}
			if(p < 0 || p > 0xFFFF) {
				fprintf(stderr,"Port %d is not a valid port number\n",p);
				exit(4);
			}
			break; }
		case 'P': path = mystrdup(optarg,"path"); break;
		case 'e': ext = mystrdup(optarg,"ext"); break;
		case 'o': {
			errno = 0;
			int offset = (int)strtol(optarg, (char **)NULL, 10);
			if(errno != 0) {
				perror("Offset not a valid integer");
			}

			hawkc_context_set_clock_offset(&ctx,offset);
			break; }
		case 'a':
			if( (algorithm = hawkc_algorithm_by_name(optarg,strlen(optarg))) == NULL) {
				fprintf(stderr,"Algorithm not known: %s\n",optarg);
				exit(4);
			}
			break;
		case 'm':
			if(strcmp("plain",optarg) == 0) {
				mode = PLAIN;
			} else if(strcmp("curl",optarg) == 0) {
				mode = CURL;
			} else if(strcmp("blitz",optarg) == 0) {
				mode = BLITZ;
			} else if(strcmp("header",optarg) == 0) {
				mode = HEADER;
			} else if(strcmp("qheader",optarg) == 0) {
				mode = QHEADER;
			} else {
				fprintf(stderr,"Mode not known: %s\n",optarg);
			}
			break;
		case 'h':
			help();
			exit(0);
		case '?':
			usage();
			exit(1);
		}
	}

	if (id == NULL) {
		usage();
		exit(2);
	}
	if (password == NULL) {
		usage();
		exit(2);
	}

	if(host == NULL) {
		usage();
		exit(1);
	}
	if(path == NULL) {
		usage();
		exit(1);
	}

	if(algorithm == NULL) {
		algorithm = HAWKC_SHA_1;
	}

	if(method == NULL) {
		method = GET;
	}
	if(port == NULL) {
		port = PORT80;
	}

	hawkc_context_set_algorithm(&ctx,algorithm);
	hawkc_context_set_password(&ctx,(unsigned char*)password, strlen(password));

	hawkc_context_set_method(&ctx,(unsigned char*)method, strlen(method));
	hawkc_context_set_path(&ctx,(unsigned char *)path, strlen(path));
	hawkc_context_set_host(&ctx,(unsigned char *)host,strlen(host));
	hawkc_context_set_port(&ctx,(unsigned char *)port,strlen(port));

	hawkc_context_set_id(&ctx,(unsigned char *)id,strlen(id));
	if(ext != NULL) {
		hawkc_context_set_ext(&ctx,(unsigned char *)ext,strlen(ext));
	}
	if( ( e = hawkc_calculate_authorization_header_length(&ctx,&required_len)) != HAWKC_OK) {
		fprintf(stderr,"Error calculating header buffer size: %s\n" , hawkc_get_error(&ctx));
		exit(2);
	}

	if( (buffer = (unsigned char *)hawkc_malloc(&ctx,required_len)) == NULL) {
		fprintf(stderr,"Unable to allocate %d bytes, %s\n" , (int)required_len, hawkc_get_error(&ctx));
		exit(3);

	}


	if( (e = hawkc_create_authorization_header(&ctx,buffer,&len)) != HAWKC_OK) {
		fprintf(stderr,"Error creating header: %s\n" , hawkc_get_error(&ctx));
		exit(4);
	}
/*
	fprintf(stdout, "req=%d, actual=%d\n" , required_len, len);
	*/

	switch(mode) {
	case PLAIN:
		fprintf(stdout, "%.*s\n", (int)len,buffer);
		break;
	case CURL:
		fprintf(stdout, "curl -v http://%s:%s%s -H 'Authorization: %.*s'", host,port,path, (int)len,buffer);
		break;
	case BLITZ:
		fprintf(stdout, "-p 1-100:60 -H 'Authorization: %.*s' http://%s:%s%s", (int)len,buffer, host,port,path);
		break;
	case HEADER:
		fprintf(stdout, "Authorization: %.*s", (int)len,buffer);
		break;
	case QHEADER:
		fprintf(stdout, "'Authorization: %.*s'", (int)len,buffer);
		break;
	}

	hawkc_free(&ctx,buffer);

	return 0;
}

void usage(void) {
	printf("Usage: hawk -i <id> -p <password> -H <host> -P <path> [-M <method>] [-O port] [-a <algorithm>] [-e <ext>] [-o <offset>] [-hv]\n");
}

void help(void) {
	printf("\n");
	printf("hawk - Generating curl commandline invocations from request data and Hawk parameters\n\n");
	printf(" \n");

	usage();

	printf("Options:\n");
	printf("    -h               Show this screen\n");
	printf("    -v               Verbose mode to print some diagnostic messages\n");
	printf("    -p <password>    Password to use for sealing/unsealing\n");
	printf("    -i <id>          Id to put in 'id' header parameter\n");
	printf("    -H <host>        Host to use for request\n");
	printf("    -P <path>        URI path to use for request\n");
	printf("    -M <method>      HTTP method to use; defaults to 'GET'\n");
	printf("    -O <port>        Port to use for request; defaults to '80'\n");
	printf("    -a <algorithm>   Algorithm to use for HMAC generation; defaults to sha1\n");
	printf("    -e <ext>         Arbitrary string to put into 'ext' header parameter\n");
	printf("    -o <offset>      Number of seconds to use for clock offset\n");
	printf("    -m <mode>        Output mode. Can be 'plain' (default), 'curl','blitz','header' or 'qheader'\n");
	printf("\n");
}
