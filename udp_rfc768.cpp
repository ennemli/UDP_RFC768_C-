#include "udp_rfc768.h"
#include <vector>
uint16_t UDPSocket::calculateUDPCheckSum(const char *data,
                                         const UDPHeader &udpHeader,
                                         size_t length,
                                         const struct sockaddr_in *srcIP,

                                         const struct sockaddr_in *destIP) {

  size_t totalSize = length + sizeof(udpHeader);
  struct PseudoHeader {
    uint32_t src_ip;    // Source IP address
    uint32_t dest_ip;   // Destination IP address
    uint8_t zeros;      // Reserved field, must be zero
    uint8_t protocol;   // Protocol number (17 for UDP)
    uint16_t udpLength; // Length of UDP header + data
  } pseudo_header;

  pseudo_header.src_ip = srcIP->sin_addr.s_addr;
  pseudo_header.dest_ip = srcIP->sin_addr.s_addr;
  pseudo_header.zeros = 0;
  pseudo_header.protocol = 17;

  if (totalSize % 2)
    totalSize++;
  pseudo_header.udpLength = htons(totalSize);
  std::vector<uint8_t> buffer(totalSize);
  uint8_t *bufPtr = buffer.data();
  size_t offset = 0;
  // Copy Pseudo Header
  memcpy(bufPtr, &pseudo_header, sizeof(PseudoHeader));
  offset += sizeof(PseudoHeader);

  // Copy UDP Header
  // and set checksum set to 0
  UDPHeader header = udpHeader;
  header.checksum = 0;
  memcpy(bufPtr + offset, &header, sizeof(UDPHeader));
  offset += sizeof(UDPHeader);

  // Copy Data
  memcpy(bufPtr + offset, data, length);

  // calculate ChceckSum
  uint32_t sum = 0;
  uint16_t *ptr = reinterpret_cast<uint16_t *>(bufPtr);

  for (size_t i = 0; i < totalSize / 2; ++i) {
    sum += ntohs(ptr[i]);
    // Handle carry
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum & 0xFFFF);
}
