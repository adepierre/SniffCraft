#pragma once

#include <vector>
#include <cstddef>
#include <fstream>


std::vector<unsigned char> Compress(const std::vector<unsigned char> &data);
std::vector<unsigned char> Decompress(const unsigned char* compressed, const size_t size);

/// @brief Compress an input file directly to an output, without loading it in memory
/// @param src_file Source file to compress
/// @param dst_file Destination file to write to
/// @return Tuple of <size of uncompressed data, size of compressed data, CRC32 of input data>
std::tuple<size_t, size_t, unsigned long> CompressRawDeflateFile(std::ifstream& src_file, std::ofstream& dst_file);
