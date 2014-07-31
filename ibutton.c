#include <stdio.h>
#include <libudev.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <wiringPi.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <pthread.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#define DEVICELISTPATH "/sys/devices/w1 bus master/w1_master_slaves"


typedef char bool;
#define true 1
#define false 0

struct peoplelist {
	char *id;
	char *name;
} people[] = {
	{ "33-0123456789ab", "Your Name Here" },
	{ NULL, NULL }
};

bool debug = false;

struct udev_monitor *mon = NULL;

void interrupt(int signal) {
	if(mon) {
		udev_monitor_filter_remove(mon);
		udev_monitor_unref(mon);
	}
	exit(0);
}

void *server(void* ignored) {
	struct sockaddr_in6 serv_addr, cli_addr;
	socklen_t clilen;
	int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	if(sockfd < 0) {
		fprintf(stderr, "Cannot create socket\n");
		return NULL;
	}
	int optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
	
	if(debug) {
		printf("Created socket %d\n", sockfd);
	}
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin6_addr = in6addr_any;
	serv_addr.sin6_family = AF_INET6;
	serv_addr.sin6_port = htons(1337);
	
	if(bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("bind");
		close(sockfd);
		return NULL;
	}
	
	listen(sockfd, 5);
	while(1) {
		clilen = sizeof(cli_addr);
		if(debug) {
			printf("Accepting new connections...\n");
		}
		int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		if(newsockfd < 0) {
			perror("accept");
			close(sockfd);
			return NULL;
		}
		unsigned char challenge[32];
		if(RAND_bytes(challenge, sizeof(challenge)) != 1) {
			fprintf(stderr, "Error %lu in RAND_bytes.\n", ERR_get_error());
			close(newsockfd);
			continue;
		}
		if(send(newsockfd, challenge, sizeof(challenge), 0) == 0) {
			perror("send");
			close(newsockfd);
			continue;
		}
		unsigned char response[SHA256_DIGEST_LENGTH];
		if(recv(newsockfd, response, sizeof(response), MSG_WAITALL) != sizeof(response)) {
			perror("recv");
			close(newsockfd);
			continue;
		}
		close(newsockfd);
		
		if(debug) {
			fprintf(stderr, "Received response: ");
			for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
				fprintf(stderr, "%02X ", response[i]);
			}
			fprintf(stderr, "\n");
		}
		
		unsigned char hash[SHA256_DIGEST_LENGTH];
		SHA256_CTX sha256;
		struct peoplelist *person = people;
		while(person->id) {
			SHA256_Init(&sha256);
			SHA256_Update(&sha256, challenge, sizeof(challenge));
			SHA256_Update(&sha256, person->id, strlen(person->id));
			SHA256_Final(hash, &sha256);

//			if(debug) {
//				fprintf(stderr, "Hash for %s: ", person->name);
//				for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
//					fprintf(stderr, "%02X ", hash[i]);
//				}
//				fprintf(stderr, "\n");
//			}
			
			bool ok = true;
			for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
				if(hash[i] != response[i]) {
					person++;
					ok = false;
					break;
				}
			}
			if(ok) {
				if(debug)
					printf("Hello, %s!\nDoor open via network.\n", person->name);
				digitalWrite(4,1);
				sleep(2);
				digitalWrite(4,0);
				if(debug)
					printf("Door closed via network.\n");
				break;
			}
		}
	}
	
	return NULL;
}

int main(int argc, char *argv[]) {
	if(argc == 1 || strcmp(argv[1], "-d")) {
		int result = fork();
		if(result == -1)
			return 1;
		else if(result != 0)
			return 0;
	} else {
		debug = true;
	}

	signal(SIGINT, interrupt);
	wiringPiSetup();
	
	pthread_t serverThread;
	
	// set up TCP server
	pthread_create(&serverThread, NULL, server, NULL);
	
	pinMode(4, OUTPUT);
	pullUpDnControl(4, PUD_OFF); // external pulldown
	
	struct udev *udev;
	udev = udev_new();
	if (!udev) {
		printf("Can't create udev\n");
		exit(1);
	}
	mon = udev_monitor_new_from_netlink(udev, "udev");
	udev_monitor_filter_add_match_subsystem_devtype(mon, "w1", NULL);
	
	// set to non-blocking
	int fd = udev_monitor_get_fd(mon);
	int flags = fcntl(fd, F_GETFL, 0);
	flags &= ~O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
	
	udev_monitor_enable_receiving(mon);
	
	while(1) {
		struct udev_device *dev = udev_monitor_receive_device(mon);
		if (dev) {
			const char *name = udev_device_get_sysname(dev);
			char found = 0;
			for(int i = 0; people[i].id; ++i) {
				if(strcmp(name, people[i].id) == 0) {
					if(debug)
						printf("Hello, %s!\n", people[i].name);
					found = 1;
					break;
				}
			}
			
			if(!found) {
				printf("Unknown device %s\n", name);
			} else {
				if(debug)
					printf("Door open.\n");
				digitalWrite(4,1);
				sleep(2);
				digitalWrite(4,0);
				if(debug)
					printf("Door closed.\n");
			}
			
			udev_device_unref(dev);
		}
		else {
			printf("No Device from receive_device(). An error occured.\n");
		}
	}
	

	return 0;
}
