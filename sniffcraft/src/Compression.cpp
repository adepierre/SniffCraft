#include "sniffcraft/Compression.hpp"

#include <zlib.h>
#include <string>
#include <cstring>
#include <stdexcept>
#include <fstream>

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

std::tuple<size_t, size_t, unsigned long> CompressRawDeflateFile(std::ifstream& src_file, std::ofstream& dst_file)
{
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    int res = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
    if (res != Z_OK)
    {
        throw(std::runtime_error("deflateInit failed: " + std::string(strm.msg)));
    }

    std::vector<char> src_buffer(8192);
    std::vector<char> dst_buffer(8192);

    size_t src_size = 0;
    size_t dst_size = 0;
    uLong crc = crc32(0L, Z_NULL, 0);

    do
    {
        src_file.read(src_buffer.data(), src_buffer.size());
        strm.avail_in = src_file.gcount();
        strm.next_in = reinterpret_cast<unsigned char*>(src_buffer.data());

        crc = crc32(crc, reinterpret_cast<const unsigned char*>(src_buffer.data()), strm.avail_in);

        do
        {
            strm.avail_out = dst_buffer.size();
            strm.next_out = reinterpret_cast<unsigned char*>(dst_buffer.data());
            deflate(&strm, src_file.eof() ? Z_FINISH : Z_NO_FLUSH);
            const std::streamsize out_count = dst_buffer.size() - strm.avail_out;
            dst_file.write(dst_buffer.data(), out_count);
            dst_size += out_count;
        } while (strm.avail_out == 0);
        src_size += strm.avail_in;
    } while (!src_file.eof());

    deflateEnd(&strm);

    return { src_size, dst_size, crc };
}
