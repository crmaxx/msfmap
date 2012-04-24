#include "../../common/common.h"
#include "msfmap.h"
#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"
#include <stdio.h>
#include "msfmap_core.h"
#include "timing_profiles.h"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

DWORD request_msfmap_init(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	msfmap_thread_info *ThreadHolder;
	msfmap_scan_options *ScanOptions;
	int i;
	unsigned int optionFlags = 0;
	unsigned int returnFlags = 0;	// has nothing to do with the thread-specifc ones. they're still initialized at 0
	unsigned short *portSpecOld;
	unsigned short *portSpecNew;
	unsigned int portSpecBufferSize = BUFFER_SIZE;
	unsigned short currentPort = 0;
	unsigned int timingProfile = 0;

	portSpecOld = (unsigned short*)packet_get_tlv_value_raw(packet, TLV_TYPE_MSFMAP_PORTS_SPECIFICATION);
	optionFlags = packet_get_tlv_value_uint(packet, TLV_TYPE_MSFMAP_SCAN_OPTIONS);

	portSpecNew = (unsigned short *)malloc(BUFFER_SIZE);
	if (portSpecNew == NULL) {
		returnFlags = (returnFlags | MSFMAP_RET_MEM_ERR);
		packet_add_tlv_uint(response, TLV_TYPE_MSFMAP_THREAD_HOLDER_LOCATION, 0);
		packet_add_tlv_uint(response, TLV_TYPE_MSFMAP_RETURN_FLAGS, returnFlags);
		packet_transmit_response(ERROR_SUCCESS, remote, response);
		return ERROR_SUCCESS;
	}
	memset(portSpecNew, 0, BUFFER_SIZE);

	while (portSpecOld[currentPort] != 0) {
		if (((currentPort + 1) * sizeof(unsigned short)) >= portSpecBufferSize) {	// plus one for the trailing 0
			portSpecNew = (unsigned short *)increaseBuffer(portSpecNew, portSpecBufferSize, BUFFER_SIZE_INCREMENT);
			if (portSpecNew == NULL) {
				returnFlags = (returnFlags | MSFMAP_RET_MEM_ERR);
				packet_add_tlv_uint(response, TLV_TYPE_MSFMAP_THREAD_HOLDER_LOCATION, (unsigned int)NULL);
				packet_add_tlv_uint(response, TLV_TYPE_MSFMAP_RETURN_FLAGS, returnFlags);
				packet_transmit_response(ERROR_SUCCESS, remote, response);

				return ERROR_SUCCESS;
			}
			portSpecBufferSize += BUFFER_SIZE_INCREMENT;
		}
		portSpecNew[currentPort] = portSpecOld[currentPort];
		currentPort++;
	}
	portSpecNew[currentPort] = 0;	// keep the null terminator
	
	ScanOptions = (msfmap_scan_options *)malloc(sizeof(msfmap_scan_options));
	if (ScanOptions == NULL) {
		returnFlags = (returnFlags | MSFMAP_RET_MEM_ERR);
		packet_add_tlv_uint(response, TLV_TYPE_MSFMAP_THREAD_HOLDER_LOCATION, (unsigned int)NULL);
		packet_add_tlv_uint(response, TLV_TYPE_MSFMAP_RETURN_FLAGS, returnFlags);
		packet_transmit_response(ERROR_SUCCESS, remote, response);

		return ERROR_SUCCESS;
	}
	memset(ScanOptions, 0, sizeof(ScanOptions));

	(*ScanOptions).optionFlags = optionFlags;
	timingProfile = (optionFlags & MSFMAP_OPTS_TIMING_FLAGS);
	switch (timingProfile) {
		case MSFMAP_OPTS_TIMING_0:
			(*ScanOptions).pingRetries = TIMING_PROFILE_0_PING_RETRIES;
			(*ScanOptions).connectTimeout_sec = TIMING_PROFILE_0_CONNECT_TIMEOUT_SEC;
			(*ScanOptions).connectTimeout_usec = TIMING_PROFILE_0_CONNECT_TIMEOUT_USEC;
			(*ScanOptions).numberOfThreads = TIMING_PROFILE_0_NUMBER_OF_THREADS;
#if defined ( DEBUG )
			printf("CORE: Setting Timing Profile To 0\n");
#endif
			break;
		case MSFMAP_OPTS_TIMING_1:
			(*ScanOptions).pingRetries = TIMING_PROFILE_1_PING_RETRIES;
			(*ScanOptions).connectTimeout_sec = TIMING_PROFILE_1_CONNECT_TIMEOUT_SEC;
			(*ScanOptions).connectTimeout_usec = TIMING_PROFILE_1_CONNECT_TIMEOUT_USEC;
			(*ScanOptions).numberOfThreads = TIMING_PROFILE_1_NUMBER_OF_THREADS;
#if defined ( DEBUG )
			printf("CORE: Setting Timing Profile To 1\n");
#endif
			break;
		case MSFMAP_OPTS_TIMING_2:
			(*ScanOptions).pingRetries = TIMING_PROFILE_2_PING_RETRIES;
			(*ScanOptions).connectTimeout_sec = TIMING_PROFILE_2_CONNECT_TIMEOUT_SEC;
			(*ScanOptions).connectTimeout_usec = TIMING_PROFILE_2_CONNECT_TIMEOUT_USEC;
			(*ScanOptions).numberOfThreads = TIMING_PROFILE_2_NUMBER_OF_THREADS;
#if defined ( DEBUG )
			printf("CORE: Setting Timing Profile To 2\n");
#endif
			break;
		case MSFMAP_OPTS_TIMING_3:
			(*ScanOptions).pingRetries = TIMING_PROFILE_3_PING_RETRIES;
			(*ScanOptions).connectTimeout_sec = TIMING_PROFILE_3_CONNECT_TIMEOUT_SEC;
			(*ScanOptions).connectTimeout_usec = TIMING_PROFILE_3_CONNECT_TIMEOUT_USEC;
			(*ScanOptions).numberOfThreads = TIMING_PROFILE_3_NUMBER_OF_THREADS;
#if defined ( DEBUG )
			printf("CORE: Setting Timing Profile To 3\n");
#endif
			break;
		case MSFMAP_OPTS_TIMING_4:
			(*ScanOptions).pingRetries = TIMING_PROFILE_4_PING_RETRIES;
			(*ScanOptions).connectTimeout_sec = TIMING_PROFILE_4_CONNECT_TIMEOUT_SEC;
			(*ScanOptions).connectTimeout_usec = TIMING_PROFILE_4_CONNECT_TIMEOUT_USEC;
			(*ScanOptions).numberOfThreads = TIMING_PROFILE_4_NUMBER_OF_THREADS;
#if defined ( DEBUG )
			printf("CORE: Setting Timing Profile To 4\n");
#endif
			break;
		case MSFMAP_OPTS_TIMING_5:
			(*ScanOptions).pingRetries = TIMING_PROFILE_5_PING_RETRIES;
			(*ScanOptions).connectTimeout_sec = TIMING_PROFILE_5_CONNECT_TIMEOUT_SEC;
			(*ScanOptions).connectTimeout_usec = TIMING_PROFILE_5_CONNECT_TIMEOUT_USEC;
			(*ScanOptions).numberOfThreads = TIMING_PROFILE_5_NUMBER_OF_THREADS;
#if defined ( DEBUG )
			printf("CORE: Setting Timing Profile To 5\n");
#endif
			break;
	}	

	ThreadHolder = (msfmap_thread_info *)malloc(CALCULATE_SIZE_OF_THREAD_HOLDER);
	if (ThreadHolder == NULL) {
		returnFlags = (returnFlags | MSFMAP_RET_MEM_ERR);
		packet_add_tlv_uint(response, TLV_TYPE_MSFMAP_THREAD_HOLDER_LOCATION, (unsigned int)NULL);
		packet_add_tlv_uint(response, TLV_TYPE_MSFMAP_RETURN_FLAGS, returnFlags);
		packet_transmit_response(ERROR_SUCCESS, remote, response);

		return ERROR_SUCCESS;
	}
	for (i = 0; i < (*ScanOptions).numberOfThreads; i++) {
		ThreadHolder[i].threadHandle = NULL;
		ThreadHolder[i].targetIP = 0;
		ThreadHolder[i].portSpec = portSpecNew;
		ThreadHolder[i].scanOptions = ScanOptions;
		ThreadHolder[i].returnFlags = 0;
		ThreadHolder[i].openPortsBufferEntries = 0;
		ThreadHolder[i].openPortsBufferSize = 0;
		ThreadHolder[i].openPortsBuffer = NULL;
	}

	packet_add_tlv_uint(response, TLV_TYPE_MSFMAP_THREAD_HOLDER_LOCATION, (unsigned int)&ThreadHolder[0]);
	packet_add_tlv_uint(response, TLV_TYPE_MSFMAP_RETURN_FLAGS, returnFlags);
	packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}

DWORD request_msfmap_core(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	msfmap_thread_info *ThreadHolder;
	unsigned char threadHolderPos = 0;
	unsigned long *packedIPaddr;
	unsigned char packedIPaddrPos = 0;
	DWORD dwRetVal = WAIT_TIMEOUT;

	(unsigned int)ThreadHolder = packet_get_tlv_value_uint(packet, TLV_TYPE_MSFMAP_THREAD_HOLDER_LOCATION);
	packedIPaddr = (unsigned long *)packet_get_tlv_value_raw(packet, TLV_TYPE_MSFMAP_IPADDRESSES);

	// put the new IPs from the array we just got into empty thread containers
	while (packedIPaddr[packedIPaddrPos] != 0) {
		// search for empty container
		while (ThreadHolder[threadHolderPos].threadHandle != NULL) {
			threadHolderPos++;
		}
		ThreadHolder[threadHolderPos].targetIP = packedIPaddr[packedIPaddrPos];
		ThreadHolder[threadHolderPos].threadHandle = CreateThread(NULL, 0, scanThread, &ThreadHolder[threadHolderPos], 0, NULL);
		threadHolderPos++;
		packedIPaddrPos++;
	}

	// all new ips have been processed, now start waiting for threads to return!
	while (dwRetVal == WAIT_TIMEOUT) {
		for (threadHolderPos = 0; threadHolderPos < ThreadHolder[0].scanOptions->numberOfThreads; threadHolderPos++) {
			if (ThreadHolder[threadHolderPos].threadHandle != NULL) {
				dwRetVal = WaitForSingleObject(ThreadHolder[threadHolderPos].threadHandle, 10);
				if (dwRetVal != WAIT_TIMEOUT) {
#if defined( DEBUG )
	printf("CORE: Thread #%i Returned.\n", threadHolderPos);
#endif
					break;
				}
			}
		}
	}

	// Cleanup the thread that returned, prepare it to be reused and harvest the info
	// harvest
	packet_add_tlv_raw(response, TLV_TYPE_MSFMAP_IPADDRESSES, &(ThreadHolder[threadHolderPos].targetIP), sizeof(unsigned long));	// only responds with the first one
	packet_add_tlv_raw(response, TLV_TYPE_MSFMAP_PORTS_OPEN, ThreadHolder[threadHolderPos].openPortsBuffer, (ThreadHolder[threadHolderPos].openPortsBufferEntries * sizeof(unsigned short)));

#if defined( DEBUG )
	printf("CORE: ReturnFlags = 0x%X\n", ThreadHolder[threadHolderPos].returnFlags);
#endif
	packet_add_tlv_uint(response, TLV_TYPE_MSFMAP_RETURN_FLAGS, ThreadHolder[threadHolderPos].returnFlags);

	// clean this thread's shit
	if (ThreadHolder[threadHolderPos].openPortsBuffer != NULL) {
		free(ThreadHolder[threadHolderPos].openPortsBuffer);
		ThreadHolder[threadHolderPos].openPortsBuffer = NULL;
	}
	ThreadHolder[threadHolderPos].threadHandle = NULL;
	ThreadHolder[threadHolderPos].targetIP = 0;
	ThreadHolder[threadHolderPos].returnFlags = 0;
	ThreadHolder[threadHolderPos].openPortsBufferEntries = 0;
	ThreadHolder[threadHolderPos].openPortsBufferSize = 0;

	packet_transmit_response(ERROR_SUCCESS, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_msfmap_cleanup(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	msfmap_thread_info *ThreadHolder;
	msfmap_scan_options *ScanOptions;
	unsigned short *portSpec;
	unsigned char threadHolderPos = 0;
	unsigned int portSpecEntries = 0;

#if defined ( DEBUG )
	printf("CORE: Cleaning Up...\n");
#endif

	(unsigned int)ThreadHolder = packet_get_tlv_value_uint(packet, TLV_TYPE_MSFMAP_THREAD_HOLDER_LOCATION);

	// get the portspec buffer from the first entry
	portSpec = ThreadHolder[0].portSpec;
	// get the number of entries in the portSpec buffer
	while (portSpec[portSpecEntries] != 0) {
		portSpecEntries++;
	}
	// clear all of the ports to 0 to make remaining threads end sooner
	memset(portSpec, 0, (portSpecEntries * sizeof(unsigned short)));

	// ensure that all threads have returned
#if defined ( DEBUG )
	printf("CORE: Waiting For Threads To Return...\n");
#endif
	for (threadHolderPos = 0; threadHolderPos < ThreadHolder[0].scanOptions->numberOfThreads; threadHolderPos++) {
		if (ThreadHolder[threadHolderPos].threadHandle != NULL) {
			WaitForSingleObject(ThreadHolder[threadHolderPos].threadHandle, INFINITE);
		}
	}
#if defined ( DEBUG )
	printf("CORE: All Threads Have Returned.\n");
#endif

	free(portSpec);	// clear and free the rest
	ScanOptions = ThreadHolder[0].scanOptions;
	memset(ScanOptions, 0, sizeof(ScanOptions));
	free(ScanOptions);
	memset(ThreadHolder, 0, CALCULATE_SIZE_OF_THREAD_HOLDER);
	free(ThreadHolder);

	packet_transmit_response(ERROR_SUCCESS, remote, response);
#if defined ( DEBUG )
	printf("CORE: Clean Up Done.\n");
#endif
	return ERROR_SUCCESS;
}

Command customCommands[] = {
	{ "msfmap_init",
		{ request_msfmap_init,			{ 0 }, 0},
		{ EMPTY_DISPATCH_HANDLER				},
	},

	{ "msfmap_core",
		{ request_msfmap_core,			{ 0 }, 0},
		{ EMPTY_DISPATCH_HANDLER				},
	},

	{ "msfmap_cleanup",
		{ request_msfmap_cleanup,		{ 0 }, 0},
		{ EMPTY_DISPATCH_HANDLER				},
	},
		
	// Terminator
	{ NULL,
		{ EMPTY_DISPATCH_HANDLER				},
		{ EMPTY_DISPATCH_HANDLER				},
	},
};

/*
 * Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote) {
	DWORD index;

	hMetSrv = remote->hMetSrv;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote) {
	DWORD index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_deregister(&customCommands[index]);

	return ERROR_SUCCESS;
}
