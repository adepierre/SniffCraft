#include <iostream>
#include "sniffcraft/server.hpp"

int main(int argc, char* argv[])
{
   if (argc < 1)
   {
      std::cerr << "usage: sniffcraft <optional:conf_path>" << std::endl;
   }

   std::string conf_path = "";
   if (argc > 1)
   {
       conf_path = argv[1];
   }

   try
   {
       Server server = Server(conf_path);
       server.run();
   }
   catch(std::exception& e)
   {
      std::cerr << "Error: " << e.what() << std::endl;
      return 1;
   }

   return 0;
}
