#pragma once

#include <vector>


std::vector<unsigned char> Compress(const std::vector<unsigned char> &data);
std::vector<unsigned char> CompressRawDeflate(const std::vector<unsigned char>& raw, const int& start = 0, const int& size = -1);
std::vector<unsigned char> Decompress(const unsigned char* compressed, const size_t size);

