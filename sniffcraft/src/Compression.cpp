#include "sniffcraft/Compression.hpp"

#include <zlib.h>
#include <string>
#include <cstring>
#include <stdexcept>

const unsigned long MAX_COMPRESSED_PACKET_LEN = 200 * 1024;

std::vector<unsigned char> Compress(const std::vector<unsigned char> &raw, const int &start, const int &size)
{
    unsigned long size_to_compress = size > 0 ? size : raw.size() - start;
    unsigned long compressedSize = compressBound(size_to_compress);

    if (compressedSize > MAX_COMPRESSED_PACKET_LEN)
    {
        throw(std::runtime_error("Incoming packet is too big"));
    }

    std::vector<unsigned char> compressedData(compressedSize);
    int status = compress2(compressedData.data(), &compressedSize, raw.data() + start, size_to_compress, Z_DEFAULT_COMPRESSION);

    if (status != Z_OK)
    {
        throw(std::runtime_error("Error compressing packet"));
    }

    return std::vector<unsigned char>(compressedData.begin(), compressedData.begin() + compressedSize);
}

std::vector<unsigned char> CompressRawDeflate(const std::vector<unsigned char>& raw, const int& start, const int& size)
{
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    strm.next_in = const_cast<unsigned char*>(raw.data() + start);
    strm.avail_in = size > 0 ? size : raw.size() - start;

    int res = deflateInit2(&strm, Z_BEST_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
    if (res != Z_OK)
    {
        throw(std::runtime_error("deflateInit failed: " + std::string(strm.msg)));
    }

    std::vector<unsigned char> compressed_data;
    std::vector<unsigned char> buffer(64 * 1024);

    int ret;
    do {
        strm.next_out = const_cast<unsigned char*>(buffer.data());
        strm.avail_out = buffer.size();

        ret = deflate(&strm, Z_FINISH);

        if (compressed_data.size() < strm.total_out)
        {
            // append the block to the output
            compressed_data.insert(compressed_data.end(), buffer.begin(), buffer.begin() + strm.total_out - compressed_data.size());
        }
    } while (ret == Z_OK);

    deflateEnd(&strm);

    if (ret != Z_STREAM_END)
    {
        throw(std::runtime_error("Deflate compression failed: " + std::string(strm.msg)));
    }

    return compressed_data;
}

std::vector<unsigned char> Decompress(const std::vector<unsigned char>& compressed, const int& start, const int& size)
{
    unsigned long size_to_decompress = size > 0 ? size : compressed.size() - start;

    std::vector<unsigned char> decompressedData;
    decompressedData.reserve(size_to_decompress);

    std::vector<unsigned char> buffer(64 * 1024);

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.next_in = const_cast<unsigned char*>(compressed.data() + start);
    strm.avail_in = size_to_decompress;
    strm.next_out = buffer.data();
    strm.avail_out = buffer.size();

    int res = inflateInit(&strm);
    if (res != Z_OK)
    {
        throw(std::runtime_error("inflateInit failed: " + std::string(strm.msg)));
    }

    for (;;)
    {
        res = inflate(&strm, Z_NO_FLUSH);
        switch (res)
        {
        case Z_OK:
            decompressedData.insert(decompressedData.end(), buffer.begin(), buffer.end() - strm.avail_out);
            strm.next_out = buffer.data();
            strm.avail_out = buffer.size();
            if (strm.avail_in == 0)
            {
                inflateEnd(&strm);
                return decompressedData;
            }
            break;
        case Z_STREAM_END:
            decompressedData.insert(decompressedData.end(), buffer.begin(), buffer.end() - strm.avail_out);
            inflateEnd(&strm);
            return decompressedData;
            break;
        default:
            inflateEnd(&strm);
            throw(std::runtime_error("Inflate decompression failed: " + std::string(strm.msg)));
            break;
        }
    }
}

