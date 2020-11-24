#include <iostream>
#include "sniffcraft/server.hpp"

int main(int argc, char* argv[])
{
   if (argc < 3)
   {
      std::cerr << "usage: sniffcraft <client_port> <server_address> <optional:logconf_path>" << std::endl;
      return 1;
   }

   const short client_port = static_cast<short>(std::atoi(argv[1]));
   const std::string server_address = argv[2];
   std::string logconf_path = "";

   if (argc == 4)
   {
       logconf_path = argv[3];
   }

   asio::io_context io_context;

   try
   {
       Server server = Server(io_context, client_port, server_address, logconf_path);
       io_context.run();
   }
   catch(std::exception& e)
   {
      std::cerr << "Error: " << e.what() << std::endl;
      return 1;
   }

   return 0;
}
