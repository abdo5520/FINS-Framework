/*
 *  *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 *
 *
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 *
 *
 * @file ethermod.c This code is based on the modified version mentioned above
 * which is provided by the Tcpdump group
 *
 * @date Nov 21, 2010
 * @author: Abdallah Abdallah
 */

#include "wifistub.h"
#include <signal.h>

#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

/*
 * app name/banner
 */
void print_app_banner(void) {

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");
	printf("\n The message printed above is a part of ");
	printf("\n the redistribution conditions requested by the Tcpdump group \n");

	return;
}

#define DEBUG
#define ERROR

/** packet inject handle */
pcap_t *inject_handle;

/** packet capture handle */
pcap_t *capture_handle;

/** Pipes Descriptors */
int capture_pipe_fd;
int inject_pipe_fd;
/**
 * Globally defined counters
 *
 */
int inject_count = 0;
int capture_count = 0;

/** handling termination ctrl+c signal
 * */

void termination_handler(int sig) {
	printf("\n**Number of captured frames = %d \n ****Number of Injected frames = %d\n", capture_count, inject_count);
	exit(2);
}

/** @brief open the incoming and outgoing NAMED PIPES
 *
 * Forking
 * Child will handle Injecting
 * Parent will handle Capturing
 *
 * Initiate Capturing
 * Initiate Injecting
 *
 * Continue Forever
 * */

int main() {

	(void) signal(SIGINT, termination_handler);
	print_app_banner();

	// ADDED mrd015 !!!!! 
	// trying to put code from fins_ethernet.sh here. This should allow mkfifo to be called w/o building coreutils for android?
	
	printf("\n\nAttempting to make " FINS_TMP_ROOT "\n");
	if (system("mkdir " FINS_TMP_ROOT) != 0) {
		printf(FINS_TMP_ROOT " already exists! Cleaning...\n");
		// if cannot create directory, assume it contains files and try to delete them
		if (system("cd " FINS_TMP_ROOT ";rm *") != 0) {
			printf("Cannot remove files in " FINS_TMP_ROOT "!\n");
		} else {
			printf(FINS_TMP_ROOT " was cleaned successfully.\n\n");
		}
	}

	if (mkfifo(CAPTURE_PIPE, 0777) != 0) {
		PRINT_DEBUG("Failed to mkfifo(CAPTURE_PIPE, 0777)");
		exit(1);
	}

	if (mkfifo(INJECT_PIPE, 0777) != 0) {
		PRINT_DEBUG("Failed to mkfifo(INJECT_PIPE, 0777)");
		exit(1);
	}
	//^^^^^END^^^^^ !!!!!	

	fflush(stdout);
	pid_t pID = 0;
	char device[20];
	//strcpy(device, "lo");
	strcpy(device, "eth0");
	//strcpy(device, "eth1");
	//strcpy(device, "eth2");
	//strcpy(device, "wlan0");

	/** Time to split into two processes
	 *  1. the child Process is for capturing (incoming)
	 *  2. the parent process is for injecting frames (outgoing)
	 */
	pID = fork();

	if (pID == 0) { // child -- Capture process
		// Code only executed by child process
		PRINT_DEBUG("child started to capture \n");
		//sleep(2);

		capture_init(device);
	} else if (pID < 0) { // failed to fork
		PRINT_DEBUG("Failed to Fork \n");
		exit(1);
	} else { // parent
		// Code only executed by parent process

		/** inject handler is supposed to be initialized earlier to make sure that forwarding
		 * feature is able to work even if the parent process did not start injecting yet
		 * we fix this by sleeping the capturing process for a while. To give the injection
		 * process a lead
		 */
		PRINT_DEBUG("parent started to Inject \n");
		inject_init(device);
	}

	/**
	 if (inject_handle != NULL);
	 pcap_close(inject_handle);

	 if (capture_handle != NULL);
	 pcap_close(capture_handle);
	 */

	return 0;
}

// end of main function
