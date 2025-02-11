#include "udp_rfc768.h"
#include <csignal>
#include <cstdlib>
#include <iostream>

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 5000
int main() {

  UDPSocket serverSocket;
  // Bind the server to an IP and port
  if (!serverSocket.bindSocket(SERVER_ADDR, SERVER_PORT)) {
    std::cerr << "Failed to bind server socket!" << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "UDP Server listening on " SERVER_ADDR << ":" << SERVER_PORT
            << "..." << std::endl;

  while (true) {
    char buffer[1024] = {0};
    std::string srcIP;
    uint16_t srcPort;

    // Receive data
    if (serverSocket.receiveFrom(srcIP, srcPort, buffer, sizeof(buffer))) {
      std::cout << "Received from " << srcIP << ":" << srcPort << " -> "
                << buffer << std::endl;

      // Send a response back
      std::string response = "Hello from UDP Server!";
      serverSocket.sendTo(srcIP, srcPort, response.c_str(), response.size());
    }
  }

  return 0;
}
