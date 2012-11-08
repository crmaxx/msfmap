#include <stdio.h>
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include <icmpapi.h>
#include "msfmap_core.h"

DWORD tcpConnect(unsigned long packedIPaddr, unsigned short portNum, msfmap_scan_options *ScanOptions) {
	/*
	 *  Returns 0 on successful connect
	 *  Returns 1 on failure to connect (network problem)
	 *  Returns 2 on failure to connect (host problem)
	 */
	struct sockaddr_in sockinfo;
	SOCKET ConnectSocket = INVALID_SOCKET;
	unsigned long NonBlk = 1;
	int iResult = 2;
	DWORD retValue = -1;

	sockinfo.sin_family = AF_INET;
	sockinfo.sin_addr.s_addr = packedIPaddr;
	sockinfo.sin_port = htons(portNum);

	ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ConnectSocket == INVALID_SOCKET) {
		return 2;
	}
	ioctlsocket(ConnectSocket, FIONBIO, &NonBlk);

	iResult = connect(ConnectSocket, (SOCKADDR*) &sockinfo, sizeof(sockinfo));
	if (iResult == SOCKET_ERROR) {
		if (WSAGetLastError() == WSAEWOULDBLOCK) {
			fd_set Write;
			fd_set Err;
			TIMEVAL Timeout;

			FD_ZERO(&Write);
			FD_ZERO(&Err);
			FD_SET(ConnectSocket, &Write);
			FD_SET(ConnectSocket, &Err);

			Timeout.tv_sec = (*ScanOptions).connectTimeout_sec;
			Timeout.tv_usec = (*ScanOptions).connectTimeout_usec;

			iResult = select((ConnectSocket + 1), NULL, &Write, &Err, &Timeout);
			if (iResult == 0) {
				retValue = 1;
			} else {
				if (FD_ISSET(ConnectSocket, &Write)) {
					retValue = 0;
				} else {
					retValue = 3;
				}
			}
		} else {
			retValue = 3;
		}
	} else {
		retValue = 0;
	}

	closesocket(ConnectSocket);
	ConnectSocket = INVALID_SOCKET;
	return retValue;
}

DWORD tcpSyn(unsigned long packedIPaddr, unsigned short portNum, msfmap_scan_options *ScanOptions) {
	/*
	 *  Returns 0 on successful connect
	 *  Returns 1 on successful response but no connect (received RST no need to retry)
	 *  Returns 2 on failure to connect (network problem)
	 *  Returns 3 on failure to connect (host problem)
	 *  Returns 4 on unknown problem
	 */
	struct sockaddr_in SockAddr;
	struct sockaddr_in SenderAddr; /* this is incoming from recvfrom() */
	struct sockaddr_in ServerAddr;
	int SenderAddrSz = sizeof(SenderAddr);
	SOCKET RawSocket = INVALID_SOCKET;
	DWORD retValue = 0;
	char sendBuffer[] = "\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02";
	char tmpSendBuffer[64];
	char tmpRecvBuffer[64];
	int tmpSendSz = 0;
	int tmpRecvSz = 64;
	struct tcp_header tcphdr;
	unsigned long srcAddr;
	unsigned short srcPort;
	unsigned short chksum = 0;
	const struct ip_header *parseiphdr;
	const struct tcp_header *parsetcphdr;
	/* next 3 are for the timeout operations */
	fd_set Read;
	TIMEVAL Timeout;

	RawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (RawSocket == INVALID_SOCKET) {
		return 2;
	}

	getSrcIPforDest(packedIPaddr, &srcAddr);
	srcPort = (unsigned short)((rand() % (RAND_PORT_MAX - RAND_PORT_MIN)) + RAND_PORT_MIN);

	SockAddr.sin_family = AF_INET;
	SockAddr.sin_addr.s_addr = packedIPaddr;
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_addr.s_addr = srcAddr;
	ServerAddr.sin_port = htons(srcPort);

	memset(&tcphdr, '\0', sizeof(tcphdr));
	tcphdr.th_sport = htons(srcPort);
	tcphdr.th_dport = htons(portNum);
	tcphdr.th_seq = htonl(rand());
	tcphdr.th_off = 32;
	tcphdr.th_f_syn = 1;
	tcphdr.th_win = htons(WINDOW_SIZE);

	memset(&tmpSendBuffer, '\0', sizeof(tmpSendBuffer));

	memcpy(tmpSendBuffer, &tcphdr, sizeof(tcphdr));
	memcpy(&tmpSendBuffer[sizeof(tcphdr)], sendBuffer, sizeof(sendBuffer));
	tmpSendSz = sizeof(tcphdr) + (sizeof(sendBuffer) - 1);

	chksum = tcp_sum_calc(tmpSendSz, (unsigned short *)&srcAddr, (unsigned short *)&packedIPaddr, (unsigned short *)&tmpSendBuffer);
	tcphdr.th_sum = chksum;
	memcpy(tmpSendBuffer, &tcphdr, sizeof(tcphdr));

	retValue = bind(RawSocket, (SOCKADDR *)&ServerAddr, sizeof(ServerAddr));
	if (retValue != 0) {
		closesocket(RawSocket);
#if defined ( DEBUG )
			printf("SCAN: Could Not Bind The Raw Socket\n");
#endif
		return 3;
	}

	retValue = sendto(RawSocket, tmpSendBuffer, tmpSendSz, 0, (SOCKADDR *)&SockAddr, sizeof(SockAddr));
	if ((retValue == SOCKET_ERROR) || (retValue != tmpSendSz)) {
		closesocket(RawSocket);
#if defined ( DEBUG )
			printf("SCAN: SendTo Failed On The Raw Socket\n");
#endif
		return 2;
	}

	/* start timeout setup */
	FD_ZERO(&Read);
	FD_SET(RawSocket, &Read);
	Timeout.tv_sec = (*ScanOptions).connectTimeout_sec;
	Timeout.tv_usec = (*ScanOptions).connectTimeout_usec;
	retValue = select(RawSocket, &Read, NULL, NULL, &Timeout);
	if (retValue == 0) {
		closesocket(RawSocket);
		return 1;
	} else if (!FD_ISSET(RawSocket, &Read)) {
		closesocket(RawSocket);
		return 2;
	}

	retValue = recvfrom(RawSocket, tmpRecvBuffer, tmpRecvSz, 0, (SOCKADDR *)&SenderAddr, &SenderAddrSz);
	closesocket(RawSocket);
	if (retValue == SOCKET_ERROR) {
		return 3;
	}

	parseiphdr = (struct ip_header*)(&tmpRecvBuffer);
	parsetcphdr = (struct tcp_header*)(tmpRecvBuffer + (IP_HL(parseiphdr) * 4));

	retValue = 3; /* this should be over written by 1 or 2 */
	if ((parsetcphdr->th_sport == tcphdr.th_dport) && (parsetcphdr->th_dport == tcphdr.th_sport) && (ntohl(parsetcphdr->th_ack) == (ntohl(tcphdr.th_seq) + 1))) {
		if ((parsetcphdr->th_f_ack == 1) && (parsetcphdr->th_f_rst == 0)) {
			retValue = 0;
		} else if (parsetcphdr->th_f_rst == 1) {
			retValue = 1;
		} else {
			retValue = 2;
		}
	} else {
		retValue = 2;
	}
	return retValue;
}

DWORD WINAPI scanThread( LPVOID lpParam) {
	msfmap_thread_info *ThreadInfo = (msfmap_thread_info *)lpParam;
	unsigned short currentPort = 0; /* Frame of reference for portSpec */
	int pingRetVal = 0;
	int pingCounter = 0;
	int scanType = ((*ThreadInfo).scanOptions->optionFlags & MSFMAP_OPTS_SCAN_TYPE_FLAGS);
	DWORD (*scanFunction)(unsigned long packedIPaddr, unsigned short portNum, msfmap_scan_options *ScanOptions) = NULL;
	unsigned short *shuffledPortList = NULL;

	/* start by checking if we should continue */
	if (iPHasDirectRoute((*ThreadInfo).targetIP) == 1) {
		for (pingCounter = 0; pingCounter < (*ThreadInfo).scanOptions->pingRetries; pingCounter++) {
			pingRetVal = arpPing((*ThreadInfo).targetIP);
			if (pingRetVal == 1) {
				break;
			}
		}
		if (pingRetVal != 1) {
			return 0;	/* host is on our LAN, but is not responding to arps. don't bother scanning. */
		}
	} else if ((*ThreadInfo).scanOptions->optionFlags & MSFMAP_OPTS_PING) {
		for (pingCounter = 0; pingCounter < (*ThreadInfo).scanOptions->pingRetries; pingCounter++) {
			pingRetVal = icmpPing((*ThreadInfo).targetIP);
			if (pingRetVal == 1) {
				break;
			}
		}
		if (pingRetVal != 1) {
			return 0;
		}
	}
	(*ThreadInfo).returnFlags = ((*ThreadInfo).returnFlags | MSFMAP_RET_HOST_UP);
	if (scanType == MSFMAP_OPTS_SCAN_TYPE_PING) {
		return 0;
	}

	/* next four are for recording open ports */
	(*ThreadInfo).openPortsBufferEntries = 0;
	(*ThreadInfo).openPortsBufferSize = BUFFER_SIZE;
	(*ThreadInfo).openPortsBuffer = (unsigned short *)malloc(BUFFER_SIZE);
	if ((*ThreadInfo).openPortsBuffer == NULL) {
		(*ThreadInfo).returnFlags = ((*ThreadInfo).returnFlags | MSFMAP_RET_MEM_ERR);
		return 0;
	}

	switch (scanType) {
		case MSFMAP_OPTS_SCAN_TYPE_TCP_CONNECT: { scanFunction = &tcpConnect; break; }
		case MSFMAP_OPTS_SCAN_TYPE_TCP_SYN: { scanFunction = &tcpSyn; break; }
		default: {
			(*ThreadInfo).returnFlags = ((*ThreadInfo).returnFlags | MSFMAP_RET_SCAN_TYPE_ERR);
			return 0;
		}
	}

	shufflePorts((*ThreadInfo).portSpec, &shuffledPortList);
	if (shuffledPortList == NULL) {
		shuffledPortList = (*ThreadInfo).portSpec;	/* see that, that's fault toleranoce */
	}

	while (shuffledPortList[currentPort] != 0) {
		if (scanFunction((*ThreadInfo).targetIP, shuffledPortList[currentPort], (*ThreadInfo).scanOptions) == 0) {
			if (((*ThreadInfo).openPortsBufferEntries * 2) >= (*ThreadInfo).openPortsBufferSize) {
				(*ThreadInfo).openPortsBuffer = (unsigned short *)increaseBuffer((*ThreadInfo).openPortsBuffer, (*ThreadInfo).openPortsBufferSize, BUFFER_SIZE_INCREMENT);
				if ((*ThreadInfo).openPortsBuffer == NULL) {
					(*ThreadInfo).returnFlags = ((*ThreadInfo).returnFlags | MSFMAP_RET_MEM_ERR);
					if (shuffledPortList != (*ThreadInfo).portSpec) {
						free(shuffledPortList);
					}
					return 0;
				}
				(*ThreadInfo).openPortsBufferSize += BUFFER_SIZE_INCREMENT;
			}
			(*ThreadInfo).openPortsBuffer[(*ThreadInfo).openPortsBufferEntries] = shuffledPortList[currentPort];
			(*ThreadInfo).openPortsBufferEntries++;
		}
		currentPort++;
	}
	if (shuffledPortList != (*ThreadInfo).portSpec) {
		free(shuffledPortList);
	}
	return 0;
}

int iPHasDirectRoute(unsigned long packedIP) {
	/*
	 *  Takes a network byte order packed IP address and iterates over the host route table looking for a local entry that corresponds to it.
	 *
	 *  Returns 1 on true, the IP is locally attached
	 *  Returns 0 on false, the IP is not in a local route
	 *  Returns a negative number signifying an error occured
	 */
	PMIB_IPFORWARDTABLE pIpForwardTable;
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;
	int i;

	pIpForwardTable = (MIB_IPFORWARDTABLE *)malloc(sizeof(MIB_IPFORWARDTABLE));
	if (pIpForwardTable == NULL) {
		return -1;
	}
	if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
		free(pIpForwardTable);
		pIpForwardTable = (MIB_IPFORWARDTABLE *)malloc(dwSize);
		if (pIpForwardTable == NULL) {
			return -2;
		}
	}
	if ((dwRetVal = GetIpForwardTable(pIpForwardTable, &dwSize, 0)) == NO_ERROR) {
		for (i=0; i < (int)pIpForwardTable->dwNumEntries; i++) {
			if (pIpForwardTable->table[i].dwForwardType == MIB_IPROUTE_TYPE_DIRECT) {
				if ((pIpForwardTable->table[i].dwForwardDest & pIpForwardTable->table[i].dwForwardMask) == (packedIP & pIpForwardTable->table[i].dwForwardMask)) {
					free(pIpForwardTable);
					return 1;	/* this ip matches a network and subnet mask that is marked as MIB_IPROUTE_TYPE_DIRCT */
				}
			}
		}
		free(pIpForwardTable);
		return 0;	/* the ip didn't match anything so it's not on our LAN */
	} else {
		free(pIpForwardTable);
		return -3;
	}
}

int getSrcIPforDest(unsigned long destIPaddr, IPAddr *sourceIPaddr) {
	int i;
	DWORD dwRetVal = NO_ERROR;
	DWORD dwBestIf = 0;
	IPAddr dwDestAddr;
	PMIB_IPADDRTABLE pIPAddrTable;
	DWORD dwSize = 0;
	IN_ADDR IPAddr;
	dwDestAddr = destIPaddr;

	dwRetVal = GetBestInterface(dwDestAddr, &dwBestIf);
	if (dwRetVal != NO_ERROR) {
		return 1;
	}
	pIPAddrTable = (MIB_IPADDRTABLE *)malloc(sizeof(MIB_IPADDRTABLE));
	if (pIPAddrTable) {
		if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
			free(pIPAddrTable);
			pIPAddrTable = (MIB_IPADDRTABLE *) malloc(dwSize);
		}
		if (pIPAddrTable == NULL) {
			return 1;
		}
	}

	if ((dwRetVal = GetIpAddrTable(pIPAddrTable, &dwSize, 0)) != NO_ERROR) { 
		return 1;
	}

	for (i=0; i < (int)pIPAddrTable->dwNumEntries; i++) {
		if (pIPAddrTable->table[i].dwIndex == dwBestIf) {
			IPAddr.S_un.S_addr = (u_long) pIPAddrTable->table[i].dwAddr;
			*sourceIPaddr = IPAddr.S_un.S_addr;
			break;
		}
	}

	if (pIPAddrTable) {
		free(pIPAddrTable);
		pIPAddrTable = NULL;
	}
	return 0;
}

int canBindRawTcp(void) {
	/*
	 *  Returns 0 on False, bind() tcp raw sockets not allowed
	 *  Returns 1 on True, bind() tcp raw sockets allowed
	 */
	struct sockaddr_in ServerAddr;
	SOCKET RawSocket = INVALID_SOCKET;
	DWORD retValue = 0;

	RawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (RawSocket == INVALID_SOCKET) {
		return 0;
	}
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	ServerAddr.sin_port = htons(1227);

	retValue = bind(RawSocket, (SOCKADDR *)&ServerAddr, sizeof(ServerAddr));
	closesocket(RawSocket);
	if (retValue == SOCKET_ERROR) {
		return 0;
	}
	return 1;
}

void shufflePorts(unsigned short *originalPortList, unsigned short **retPortList) {
	/* if we couldn't malloc the necessary amount of memory newPortList will be NULL so check it! */
	/* this is not crypto graphically secure but it gets the job done */
	/* don't forget to free the block when done with it */
	unsigned int numberOfPorts = 0;
	unsigned int currentPort = 0;
	unsigned int k = 0;
	unsigned short tmpPortHolder = 0;
	unsigned short *newPortList = NULL;

	while (originalPortList[currentPort] != 0) {
		numberOfPorts++;
		currentPort++;
	}

	newPortList = (unsigned short *)malloc((sizeof(unsigned short) * numberOfPorts) + 1);
	*retPortList = newPortList;
	if (newPortList == NULL) {
		return;
	}
	memcpy(newPortList, originalPortList, (sizeof(unsigned short) * numberOfPorts));
	newPortList[numberOfPorts] = 0;
	currentPort = 0;

	while (originalPortList[currentPort] != 0) {
		k = (rand() % (numberOfPorts - currentPort));
		tmpPortHolder = newPortList[currentPort];
		newPortList[currentPort] = newPortList[k];
		newPortList[k] = tmpPortHolder;
		currentPort++;
	}
	return;
}

int arpPing(unsigned long packedIP) {
	/*
	 *  Checks ARP cache and thens searchs for an ARP response. Check the MSDN documentation for SendARP for more info
	 * 
	 *  Returns 1 on true, the IP has a valid ARP entry
	 *  Retunrs 0 on false, the IP does not have a valid ARP entry
	 *  Returns a negative number signifying an error occured
	 */
	DWORD dwRetVal;
	IPAddr DestIp = 0;
	IPAddr SrcIp = 0;
	ULONG MacAddr[2];
	ULONG PhysAddrLen = 6;

	DestIp = packedIP;
	memset(&MacAddr, 0xff, sizeof(MacAddr));
	dwRetVal = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);

	if (dwRetVal == NO_ERROR) {
		return 1;
	}
	return 0;
}

int icmpPing(unsigned long packedIP) {
	/* 
	 *  Sends an ICMP Echo request.
	 * 
	 *  Returns 1 on successful host resposne
	 *  Returns 0 on no response
	 *  Returns a negative number on error
	 */
	HANDLE hIcmpFile;
	unsigned long ipaddr = INADDR_NONE;
	DWORD dwRetVal = 0;
	char SendData[32] = "abcdefghijklmnopqrstuvwabcdefghi";	// mimics windows
	LPVOID ReplyBuffer = NULL;
	DWORD ReplySize = 0;
	hIcmpFile = IcmpCreateFile();
	if (hIcmpFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);

	ReplyBuffer = (void *)malloc(ReplySize);
	if (ReplyBuffer == NULL) {
		return -2;
	}

	dwRetVal = IcmpSendEcho(hIcmpFile, packedIP, SendData, sizeof(SendData), NULL, ReplyBuffer, ReplySize, 500);
	if (dwRetVal != 0) {
		return 1;
	} else {
		return 0;
	}
	return 0;
}

LPVOID increaseBuffer(void *currentBuffer, unsigned int currentBufferSize, unsigned int bufferIncrement) {
	void *newBuffer = malloc(currentBufferSize + bufferIncrement);
	if (newBuffer == NULL) {
		return NULL;
	}
	memcpy(newBuffer, currentBuffer, currentBufferSize);
	free(currentBuffer);
	return newBuffer;
}

unsigned short tcp_sum_calc(unsigned short len_tcp, unsigned short src_addr[],unsigned short dest_addr[], unsigned short buff[]) {
	unsigned char prot_tcp = 6;
	unsigned long sum;
	int nleft;
	unsigned short *w;

	sum = 0;
	nleft = len_tcp;
	w = buff;

	/* calculate the checksum for the tcp header and payload */
	while(nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
	if(nleft>0) {
		sum += *w&ntohs(0xFF00); /* Thanks to Dalton */
	}

	/* add the pseudo header */
	sum += src_addr[0];
	sum += src_addr[1];
	sum += dest_addr[0];
	sum += dest_addr[1];
	sum += htons(len_tcp);
	sum += htons(prot_tcp);

	/* keep only the last 16 bits of the 32 bit calculated sum and add the carries */
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	/* Take the one's complement of sum */
	sum = ~sum;
	return ((unsigned short) sum);
}
