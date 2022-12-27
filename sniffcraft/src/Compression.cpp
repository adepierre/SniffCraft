#include "sniffcraft/Compression.hpp"

#include <zlib.h>
#include <string>
#include <cstring>
#include <stdexcept>

constexpr size_t MAX_COMPRESSED_PACKET_LEN = 200 * 1024;

std::vector<unsigned char> Compress(const std::vector<unsigned char> &data)
{
    unsigned long compressed_size = compressBound(data.size());

    if (compressed_size > MAX_COMPRESSED_PACKET_LEN)
    {
        throw(std::runtime_error("Incoming packet is too big"));
    }

    std::vector<unsigned char> compressed_data(compressed_size);
    int status = compress2(compressed_data.data(), &compressed_size, data.data(), data.size(), Z_DEFAULT_COMPRESSION);

    if (status != Z_OK)
    {
        throw(std::runtime_error("Error compressing packet"));
    }

    // Shrink to keep only real data
    compressed_data.resize(compressed_size);
    return compressed_data;
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

std::vector<unsigned char> Decompress(const unsigned char* compressed, const size_t size)
{
    std::vector<unsigned char> decompressed_data;
    decompressed_data.reserve(size);

    std::vector<unsigned char> buffer(64 * 1024);

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.next_in = const_cast<unsigned char*>(compressed);
    strm.avail_in = size;
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
            decompressed_data.insert(decompressed_data.end(), buffer.begin(), buffer.end() - strm.avail_out);
            strm.next_out = buffer.data();
            strm.avail_out = buffer.size();
            if (strm.avail_in == 0)
            {
                inflateEnd(&strm);
                return decompressed_data;
            }
            break;
        case Z_STREAM_END:
            decompressed_data.insert(decompressed_data.end(), buffer.begin(), buffer.end() - strm.avail_out);
            inflateEnd(&strm);
            return decompressed_data;
            break;
        default:
            inflateEnd(&strm);
            throw(std::runtime_error("Inflate decompression failed: " + std::string(strm.msg)));
            break;
        }
    }
}

