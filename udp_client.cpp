#include "udp_rfc768.h"
#include <cstdint>
#include <iostream>
#include <string>
#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 5122
int main() {
  UDPSocket clientSocket;
  std::string message = "Hello UDP Server!";
  clientSocket.bindSocket("127.0.0.5", 4090);
  // Send message to the server
  if (clientSocket.sendTo(SERVER_ADDR, SERVER_PORT, message.c_str(),
                          message.size())) {
    std::cout << "Message sent to " << SERVER_ADDR << ":" << SERVER_PORT
              << std::endl;
  } else {
    std::cerr << "Failed to send message!" << std::endl;
  }

  // Receive response from server
  char buffer[1024] = {0};
  std::string srcIP;
  uint16_t srcPort;
  if (clientSocket.receiveFrom(srcIP, srcPort, buffer, sizeof(buffer))) {
    std::cout << "Response from " << SERVER_ADDR << ":" << SERVER_PORT << " -> "
              << buffer << std::endl;
  }

  return 0;
}
