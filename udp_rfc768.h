#include "netinet/in.h"
#include "sys/socket.h"
#include "unistd.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#define MAX_PACKET_BUFFER 65536
struct UDPHeader {
  uint16_t source_port;
  uint16_t dest_port;
  uint16_t length;
  uint16_t checksum;
} __attribute__((packed));
class UDPSocket {
private:
  int sockfd;
  struct sockaddr_in localAddr;

  uint16_t calculateUDPCheckSum(const char *data, const UDPHeader &udpHeader,
                                size_t length, const struct sockaddr_in *srcIP,

                                const struct sockaddr_in *destIP);
  uint16_t calculateIPChecksum(struct ip *ipHeader);

public:
  UDPSocket();
  ~UDPSocket();
  bool bindSocket(const std::string &ip, uint16_t port);
  bool sendTo(const std::string &destIP, uint16_t destPort, const char *data,
              size_t length);
  bool receiveFrom(std::string &srcIP, uint16_t &srcPort, char *buffer,
                   size_t bufferSize);
  void cleanUp();
  int socketFd() { return sockfd; };
};
