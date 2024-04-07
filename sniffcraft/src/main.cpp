#include <iostream>
#include <string_view>
#include "sniffcraft/conf.hpp"
#include "sniffcraft/server.hpp"

int main(int argc, char* argv[])
{
   if (argc < 1)
   {
      std::cerr << "usage: sniffcraft <optional:--headless> <optional:conf_path>" << std::endl;
   }

   if (argc > 1)
   {
       for (int i = 1; i < argc; ++i)
       {
           if (std::string_view(argv[i]) == "--headless")
           {
               Conf::headless = true;
           }
           else
           {
               Conf::conf_path = argv[i];
           }
       }
   }

   try
   {
       Server server = Server();
       server.run();
   }
   catch(std::exception& e)
   {
      std::cerr << "Error: " << e.what() << std::endl;
      return 1;
   }

   return 0;
}
