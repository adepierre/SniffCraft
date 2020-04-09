#include <iostream>
#include "sniffcraft/server.hpp"

int main(int argc, char* argv[])
{
   if (argc < 4)
   {
      std::cerr << "usage: sniffcraft <client_port> <server_address> <server_port> <optional:logconf_path>" << std::endl;
      return 1;
   }

   const short client_port = static_cast<short>(std::atoi(argv[1]));
   const short server_port = static_cast<short>(std::atoi(argv[3]));
   const std::string server_address = argv[2];
   std::string logconf_path = "";

   if (argc == 5)
   {
       logconf_path = argv[4];
   }

   asio::io_context io_context;

   try
   {
       Server server = Server(io_context, client_port, server_address, server_port, logconf_path);
       io_context.run();
   }
   catch(std::exception& e)
   {
      std::cerr << "Error: " << e.what() << std::endl;
      return 1;
   }

   return 0;
}

/*
 * [Note] On posix systems the tcp proxy server build command is as follows:
 * c++ -pedantic -ansi -Wall -Werror -O3 -o tcpproxy_server tcpproxy_server.cpp -L/usr/lib -lstdc++ -lpthread -lboost_thread -lboost_system
 */