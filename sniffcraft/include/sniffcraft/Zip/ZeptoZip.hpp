#pragma once

#include <string>
#include <vector>

// Can we have a Zip library?
// We already have a Zip library at home
// Zip library at home:
class ZeptoZip
{
public:
    // Pack a list of files into a zip archive at outpath.
    // If compression is true, file content is compressed
    // using zlib.
    // This is a very very very simple zip implementation
    // barely sufficient for sniffcraft use. Might not be
    // suitable for anything else
    static void CreateZipArchive(const std::string& outpath, const std::vector<std::string>& inputs, const std::vector<std::string>& filenames, const std::vector<bool>& compression);
};