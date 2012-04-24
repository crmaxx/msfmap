#ifndef _METERPRETER_SOURCE_EXTENSION_MSFMAP_MSFMAP_H
#define _METERPRETER_SOURCE_EXTENSION_MSFMAP_MSFMAP_H
#endif

#include <Ipexport.h>

/* #define DEBUG */

#define BUFFER_SIZE 1024	// 512 packed ports or 256 packed ips
#define BUFFER_SIZE_INCREMENT 512
#define NUMBER_OF_THREADS 16
#define WINDOW_SIZE 8192
#define CALCULATE_SIZE_OF_THREAD_HOLDER (sizeof(msfmap_thread_info) * (*ScanOptions).numberOfThreads)
#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)

#define MSFMAP_OPTS_SCAN_TYPE_FLAGS				0xf0000000
#define MSFMAP_OPTS_SCAN_TYPE_TCP_CONNECT		0x10000000
#define MSFMAP_OPTS_SCAN_TYPE_PING				0x20000000
#define MSFMAP_OPTS_SCAN_TYPE_TCP_SYN			0x30000000
#define MSFMAP_OPTS_TIMING_FLAGS				0x0e000000
#define MSFMAP_OPTS_TIMING_0					0x02000000
#define MSFMAP_OPTS_TIMING_1					0x04000000
#define MSFMAP_OPTS_TIMING_2					0x06000000
#define MSFMAP_OPTS_TIMING_3					0x08000000
#define MSFMAP_OPTS_TIMING_4					0x0a000000
#define MSFMAP_OPTS_TIMING_5					0x0c000000
#define MSFMAP_OPTS_PING						0x01000000

#define MSFMAP_RET_HOST_UP 0x1
#define MSFMAP_RET_ERROR_FLAGS 0xffff0000
#define MSFMAP_RET_MEM_ERR 0x20000
#define MSFMAP_RET_SCAN_TYPE_ERR 0x40000

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

typedef unsigned int tcp_seq;

/* TCP header */
struct tcp_header {
	unsigned short th_sport;		/* source port */
	unsigned short th_dport;		/* destination port */
	tcp_seq th_seq;					/* sequence number */
	tcp_seq th_ack;					/* acknowledgement number */
	unsigned char  th_res:2;
	unsigned char  th_off:6;
	unsigned char  th_f_fin:1;
	unsigned char  th_f_syn:1;
	unsigned char  th_f_rst:1;
	unsigned char  th_f_psh:1;
	unsigned char  th_f_ack:1;
	unsigned char  th_f_urg:1;
	unsigned char  th_f_ecn:1;
	unsigned char  th_f_cwr:1;
	unsigned short th_win;			/* window */
	unsigned short th_sum;			/* checksum */
	unsigned short th_urp;
};

/* IP header */
struct ip_header {
	unsigned char  ip_vhl;			/* version << 4 | header length >> 2 */
	unsigned char  ip_tos;			/* type of service */
	unsigned short ip_len;			/* total length */
	unsigned short ip_id;			/* identification */
	unsigned short ip_off;			/* fragment offset field */
	unsigned char  ip_ttl;			/* time to live */
	unsigned char  ip_p;			/* protocol */
	unsigned short ip_sum;			/* checksum */
	struct  in_addr ip_src,ip_dst;	/* source and dest address */
};

DWORD tcpConnect(unsigned long packedIPaddr, unsigned short portNum, msfmap_scan_options *ScanOptions);
DWORD tcpSyn(unsigned long packedIPaddr, unsigned short portNum, void *ScanOptions);
DWORD WINAPI scanThread( LPVOID lpParam );
int iPHasDirectRoute(unsigned long packedIP);
int getSrcIPforDest(unsigned long destIPaddr, IPAddr *sourceIPaddr);
int arpPing(unsigned long packedIP);
int icmpPing(unsigned long packedIP);
LPVOID increaseBuffer(void *currentBuffer, unsigned int currentBufferSize, unsigned int bufferIncrement);
unsigned short tcp_sum_calc(unsigned short len_tcp, unsigned short src_addr[], unsigned short dest_addr[], unsigned short buff[]);