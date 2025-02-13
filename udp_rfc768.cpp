#include "udp_rfc768.h"
#include "arpa/inet.h"
#include "netinet/ip.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <vector>
UDPSocket::UDPSocket() {
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  if (sockfd < 0) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  // Enable IP_HDRINCL to manually build headers
  int optval = 1;
  if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
    perror("setsockopt failed");
    exit(EXIT_FAILURE);
  }
  struct timeval tv;
  tv.tv_sec = 5; // 5 second timeout
  tv.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  // Enable SO_REUSEADDR to allow socket to be quickly reused after shutdown
  int reuseAddr = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr));
}
void UDPSocket::cleanUp() {
  if (sockfd >= 0) {
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
    sockfd = -1;
  }
}
UDPSocket::~UDPSocket() { cleanUp(); }

bool UDPSocket::bindSocket(const std::string &ip, uint16_t port) {
  memset(&localAddr, 0, sizeof(localAddr));
  localAddr.sin_family = AF_INET;
  localAddr.sin_port = htons(port);

  inet_pton(AF_INET, ip.c_str(), &localAddr.sin_addr);
  if (bind(sockfd, (struct sockaddr *)&localAddr, sizeof(localAddr)) < 0) {
    perror("Bind failed");
    return false;
  }
  return true;
}

bool UDPSocket::sendTo(const std::string &destIP, uint16_t destPort,
                       const char *data, size_t length) {
  constexpr size_t iplen = sizeof(struct ip);
  constexpr size_t udpHeaderLen = sizeof(UDPHeader);
  struct sockaddr_in destAddr;
  memset(&destAddr, 0, sizeof(destAddr));
  destAddr.sin_family = AF_INET;
  destAddr.sin_port = htons(destPort);
  inet_pton(AF_INET, destIP.c_str(), &destAddr.sin_addr);
  // Construct UDP header
  UDPHeader udpHeader;
  udpHeader.source_port = localAddr.sin_port;
  udpHeader.dest_port = destAddr.sin_port;
  udpHeader.length = htons(sizeof(UDPHeader) + length);
  udpHeader.checksum = 0; // Initially set to 0

  // Construct IP header
  struct ip ipHeader;

  size_t packetSize = iplen + udpHeaderLen + length;
  ipHeader.ip_hl = 5;
  ipHeader.ip_v = 4;
  ipHeader.ip_tos = 0;
  ipHeader.ip_len = htons(packetSize);
  ipHeader.ip_id = htons(54321);
  ipHeader.ip_off = 0;
  ipHeader.ip_ttl = 64;
  ipHeader.ip_p = IPPROTO_UDP;
  ipHeader.ip_src = localAddr.sin_addr;
  ipHeader.ip_dst = destAddr.sin_addr;
  ipHeader.ip_sum = calculateIPChecksum(&ipHeader);
  // Calculate UDP checksum
  udpHeader.checksum =
      calculateUDPCheckSum(data, udpHeader, length, &localAddr, &destAddr);

  // Construct packet
  std::vector<char> packet(packetSize);
  memcpy(packet.data(), &ipHeader, iplen);
  memcpy(packet.data() + iplen, &udpHeader, udpHeaderLen);
  memcpy(packet.data() + iplen + udpHeaderLen, data, length);
  // Send packet

  ssize_t sent = sendto(sockfd, packet.data(), packetSize, 0,
                        (struct sockaddr *)&destAddr, sizeof(destAddr));
  return sent == static_cast<ssize_t>(packetSize);
}

bool UDPSocket::receiveFrom(std::string &srcIP, uint16_t &srcPort, char *buffer,
                            size_t bufferSize) {

  char recvBuffer[MAX_PACKET_BUFFER];
  struct sockaddr_in senderAddr;
  socklen_t addrLen = sizeof(senderAddr);

  ssize_t bytesReceived = recvfrom(sockfd, recvBuffer, sizeof(recvBuffer), 0,
                                   (struct sockaddr *)&senderAddr, &addrLen);
  if (bytesReceived <= 0) {

    return false;
  }

  // Extract IP header
  std::unique_ptr<struct ip> ipHeader = std::make_unique<struct ip>();
  memcpy(ipHeader.get(), recvBuffer, sizeof(struct ip));
  size_t ipHeaderLen = ipHeader->ip_hl * 4; // IP header length in bytes
  if (ipHeader->ip_p != IPPROTO_UDP) {

    return false;
  }
  // Extract UDP header
  std::unique_ptr<UDPHeader> udpHeader = std::make_unique<UDPHeader>();
  memcpy(udpHeader.get(), recvBuffer + ipHeaderLen, sizeof(UDPHeader));
  size_t udpPayloadSize = ntohs(udpHeader->length) - sizeof(UDPHeader);
  // Validate buffer size
  if (udpPayloadSize > bufferSize) {
    std::cerr << "Buffer too small for payload" << std::endl;
    return false;
  }

  // Save the received checksum and zero it for verification
  uint16_t receivedChecksum = udpHeader->checksum;
  udpHeader->checksum = 0;

  // Calculate checksum on received data
  uint16_t computedChecksum = calculateUDPCheckSum(
      recvBuffer + ipHeaderLen + sizeof(UDPHeader), // payload data
      *udpHeader, udpPayloadSize, &senderAddr, &localAddr);

  if (computedChecksum != receivedChecksum) {
    std::cerr << "UDP checksum verification failed!" << std::endl;
    return false;
  }

  // Copy payload to user buffer
  memcpy(buffer, recvBuffer + ipHeaderLen + sizeof(UDPHeader), udpPayloadSize);
  buffer[udpPayloadSize] = '\0'; // Null-terminate

  // Set source information
  srcIP = inet_ntoa(senderAddr.sin_addr);
  srcPort = ntohs(udpHeader->source_port);

  return true;
}

uint16_t UDPSocket::calculateUDPCheckSum(const char *data,
                                         const UDPHeader &udpHeader,
                                         size_t length,
                                         const struct sockaddr_in *srcIP,
                                         const struct sockaddr_in *destIP) {
  struct PseudoHeader {
    uint32_t src_ip;    // Source IP address
    uint32_t dest_ip;   // Destination IP address
    uint8_t zeros;      // Reserved field, must be zero
    uint8_t protocol;   // Protocol number (17 for UDP)
    uint16_t udpLength; // Length of UDP header + data
  } pseudo_header;

  // Calculate total size for UDP data + header
  size_t udpTotalSize = sizeof(UDPHeader) + length;
  if (udpTotalSize % 2)
    udpTotalSize++; // Pad to even length if necessary

  // Set pseudo header fields
  pseudo_header.src_ip = srcIP->sin_addr.s_addr;
  pseudo_header.dest_ip = destIP->sin_addr.s_addr;
  pseudo_header.zeros = 0;
  pseudo_header.protocol = IPPROTO_UDP;
  pseudo_header.udpLength = htons(udpTotalSize);

  // Allocate buffer for pseudo header + UDP header + data
  size_t totalSize = sizeof(PseudoHeader) + udpTotalSize;
  std::vector<uint8_t> buffer(totalSize, 0); // Initialize with zeros

  // Copy all parts into buffer
  size_t offset = 0;
  memcpy(buffer.data(), &pseudo_header, sizeof(PseudoHeader));
  offset += sizeof(PseudoHeader);

  // Copy UDP header (with checksum = 0)
  UDPHeader header = udpHeader;
  header.checksum = 0;
  memcpy(buffer.data() + offset, &header, sizeof(UDPHeader));
  offset += sizeof(UDPHeader);

  // Copy payload data
  memcpy(buffer.data() + offset, data, length);

  // Calculate checksum over entire buffer
  uint32_t sum = 0;
  uint16_t *ptr = reinterpret_cast<uint16_t *>(buffer.data());

  for (size_t i = 0; i < totalSize / 2; ++i) {
    sum += ntohs(ptr[i]);
    if (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
  }

  return ~sum & 0xFFFF;
}
uint16_t UDPSocket::calculateIPChecksum(struct ip *ipHeader) {
  uint32_t sum = 0;
  uint16_t *headerPtr = reinterpret_cast<uint16_t *>(ipHeader);

  for (size_t i = 0; i < sizeof(struct ip) / 2; ++i) {

    sum += ntohs(headerPtr[i]);

    if (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
  }

  return static_cast<uint16_t>(~sum & 0xFFFF);
}
