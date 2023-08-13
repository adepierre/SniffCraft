#include "sniffcraft/FileUtilities.hpp"

#include <sys/types.h>
#include <sys/stat.h>

#ifndef WIN32
#include <unistd.h>
#else
#define stat _stat
#endif

const std::time_t GetModifiedTimestamp(const std::string& path)
{
    struct stat result;
    if (stat(path.c_str(), &result) == 0)
    {
        return result.st_mtime;
    }
    return -1;
}
