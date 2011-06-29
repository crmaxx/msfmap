#ifndef _METERPRETER_SOURCE_EXTENSION_MSFMAP_MSFMAP_H
#define _METERPRETER_SOURCE_EXTENSION_MSFMAP_MSFMAP_H
#endif

// #define DEBUG

#define BUFFER_SIZE 1024	// 512 packed ports or 256 packed ips
#define BUFFER_SIZE_INCREMENT 512
#define NUMBER_OF_THREADS 16
#define CALCULATE_SIZE_OF_THREAD_HOLDER (sizeof(msfmap_thread_info) * (*ScanOptions).numberOfThreads)

#define MSFMAP_OPTS_PING 0x1000000
#define MSFMAP_OPTS_TIMING_FLAGS 0xe000000
#define MSFMAP_OPTS_TIMING_0 0x2000000
#define MSFMAP_OPTS_TIMING_1 0x4000000
#define MSFMAP_OPTS_TIMING_2 0x6000000
#define MSFMAP_OPTS_TIMING_3 0x8000000
#define MSFMAP_OPTS_TIMING_4 0xa000000
#define MSFMAP_OPTS_TIMING_5 0xc000000

#define MSFMAP_RET_HOST_UP 0x1
#define MSFMAP_RET_ERROR_FLAGS 0xffff0000
#define MSFMAP_RET_MEM_ERR 0x20000

typedef struct msfmap_scan_options {
	unsigned int optionFlags;
	int pingRetries;
	int connectTimeout_sec;
	int connectTimeout_usec;
	int numberOfThreads;
} msfmap_scan_options;

typedef struct msfmap_thread_info {
	HANDLE WINAPI threadHandle;
	unsigned long targetIP;
	unsigned short *portSpec;							// ports to scan, this is the same across all threads and should never be modified
	msfmap_scan_options *scanOptions;
	unsigned int returnFlags;
	// next three are for recording open ports
	unsigned int openPortsBufferEntries;				// number of entries in the buffer, (size being used is this * 2)
	unsigned int openPortsBufferSize;					// the initial size of the buffer (space available)
	unsigned short *openPortsBuffer;					// pointer to the initial buffer that will be malloc'd
} msfmap_thread_info;

DWORD tcpConnect(unsigned long packedIPaddr, unsigned short portNum, msfmap_scan_options *ScanOptions);
DWORD WINAPI scanThread( LPVOID lpParam );
int iPHasDirectRoute(unsigned long packedIP);
int arpPing(unsigned long packedIP);
icmpPing(unsigned long packedIP);
LPVOID increaseBuffer(void *currentBuffer, unsigned int currentBufferSize, unsigned int bufferIncrement);
