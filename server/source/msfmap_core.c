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
	 *	Returns 0 on successful connect
	 *	Returns 1 on failure to connect (network problem)
	 *	Returns 2 on failure to connect (host problem)
	 */
	struct sockaddr_in sockinfo;
	SOCKET ConnectSocket = INVALID_SOCKET;
	unsigned long NonBlk = 1;
	int iResult = 2;
	DWORD Err;
	DWORD retValue = -1;
	
	DWORD StartTime = 0;
	DWORD EndTime = 0;

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

			StartTime = GetTickCount();
			iResult = select(0, NULL, &Write, NULL, &Timeout);
			EndTime = GetTickCount();
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

DWORD WINAPI scanThread( LPVOID lpParam) {
	msfmap_thread_info *ThreadInfo = (msfmap_thread_info *)lpParam;
	unsigned short currentPort = 0; // Frame of reference for portSpec
	int pingRetVal = 0;
	int pingCounter = 0;
	int scanType = ((*ThreadInfo).scanOptions->optionFlags & MSFMAP_OPTS_SCAN_TYPE_FLAGS);

	// start by checking if we should continue
	if (iPHasDirectRoute((*ThreadInfo).targetIP) == 1) {
		for (pingCounter = 0; pingCounter < (*ThreadInfo).scanOptions->pingRetries; pingCounter++) {
			pingRetVal = arpPing((*ThreadInfo).targetIP);
			if (pingRetVal == 1) {
				break;
			}
		}
		if (pingRetVal != 1) {
			return 0;	// host is on our LAN, but is not responding to arps. don't bother scanning.
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

	// next four are for recording open ports
	(*ThreadInfo).openPortsBufferEntries = 0;
	(*ThreadInfo).openPortsBufferSize = BUFFER_SIZE;
	(*ThreadInfo).openPortsBuffer = (unsigned short *)malloc(BUFFER_SIZE);
	if ((*ThreadInfo).openPortsBuffer == NULL) {
		(*ThreadInfo).returnFlags = ((*ThreadInfo).returnFlags | MSFMAP_RET_MEM_ERR);
		return 0;
	}

	while ((*ThreadInfo).portSpec[currentPort] != 0) {
		if (tcpConnect((*ThreadInfo).targetIP, (*ThreadInfo).portSpec[currentPort], (*ThreadInfo).scanOptions) == 0) {
			if (((*ThreadInfo).openPortsBufferEntries * 2) >= (*ThreadInfo).openPortsBufferSize) {
				(*ThreadInfo).openPortsBuffer = (unsigned short *)increaseBuffer((*ThreadInfo).openPortsBuffer, (*ThreadInfo).openPortsBufferSize, BUFFER_SIZE_INCREMENT);
				if ((*ThreadInfo).openPortsBuffer == NULL) {
					(*ThreadInfo).returnFlags = ((*ThreadInfo).returnFlags | MSFMAP_RET_MEM_ERR);
					return 0;
				}
				(*ThreadInfo).openPortsBufferSize += BUFFER_SIZE_INCREMENT;
			}
			(*ThreadInfo).openPortsBuffer[(*ThreadInfo).openPortsBufferEntries] = (*ThreadInfo).portSpec[currentPort];
			(*ThreadInfo).openPortsBufferEntries++;
		}
		currentPort++;
	}
	return 0;
}

int iPHasDirectRoute(unsigned long packedIP) {
	/*
	 * Takes a network byte order packed IP address and iterates over the host route table looking for a local entry that corresponds to it.
	 *
	 * Returns 1 on true, the IP is locally attached
	 * Retunrs 0 on false, the IP is not in a local route
	 * Returns a negative number signifying an error occured
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
					return 1;	// this ip matches a network and subnet mask that is marked as MIB_IPROUTE_TYPE_DIRCT
				}
			}
		}
		free(pIpForwardTable);
		return 0;	// the ip didn't match anything so it's not on our LAN
	} else {
		free(pIpForwardTable);
		return -3;
	}
}

int arpPing(unsigned long packedIP) {
	/*
	 * Checks ARP cache and thens searchs for an ARP response. Check the MSDN documentation for SendARP for more info
	 * 
	 * Returns 1 on true, the IP has a valid ARP entry
	 * Retunrs 0 on false, the IP does not have a valid ARP entry
	 * Returns a negative number signifying an error occured
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
	 * Sends an ICMP Echo request.
	 * 
	 * Returns 1 on successful host resposne
	 * Returns 0 on no response
	 * Returns a negative number on error
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
