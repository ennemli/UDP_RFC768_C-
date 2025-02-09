#include "netinet/in.h"
#include "sys/socket.h"
#include "unistd.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
struct IPHeader {
  uint8_t version : 4;
  uint8_t ihl : 4;
  uint8_t tos;
  uint16_t total_length;
  uint16_t id;
  uint16_t fragment_offset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t src_ip;
  uint32_t dest_ip;
};

struct UDPHeader {
  uint16_t source_port;
  uint16_t dest_port;
  uint16_t length;
  uint16_t checksum;
};
class UDPSocket {
private:
  int sockfd;
  struct sockaddr_in localAddr;

  uint16_t calculateUDPCheckSum(const char *data, const UDPHeader &udpHeader,
                                size_t length, const struct sockaddr_in *srcIP,

                                const struct sockaddr_in *destIP);

  bool bindSocket(const std::string &ip, uint16_t port);
};
