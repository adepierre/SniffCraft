#include "sniffcraft/Zip/ZeptoZip.hpp"
#include "sniffcraft/Zip/CRC32.hpp"
#include "sniffcraft/Zip/DosTime.hpp"
#include "sniffcraft/Compression.hpp"

#include <fstream>
#include <assert.h>

void ZeptoZip::CreateZipArchive(const std::string& outpath, const std::vector<std::string>& inputs, const std::vector<std::string>& filenames, const std::vector<bool>& compression)
{
    // We assume inputs.size() == filenames.size() == compression.size()

    std::ofstream out(outpath, std::ios::out | std::ios::binary);
    const unsigned int msdos_now = DosTime::Now();

    std::vector<unsigned int> crcs(inputs.size());
    std::vector<unsigned int> compressed_sizes(inputs.size());
    std::vector<unsigned int> raw_sizes(inputs.size());
    std::vector<unsigned short> filename_sizes(inputs.size());
    std::vector<unsigned int> header_offsets(inputs.size());

    unsigned short number_of_records = inputs.size();

    unsigned int bytes_added_files = 0;
    unsigned int bytes_added_central_directory = 0;

    // All files
    for (int i = 0; i < inputs.size(); ++i)
    {
        // open the file
        std::ifstream file(inputs[i], std::ios::binary);
        // read the data
        std::vector<unsigned char> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // Get values for later
        crcs[i] = CRC32::Update(0, data);
        std::vector<unsigned char> compressed;
        // Compression if needed
        // (TODO, directly compress from the
        // input file into the output file would be smart)
        if (compression[i])
        {
            compressed = CompressRawDeflate(data);
        }
        compressed_sizes[i] = compression[i] ? compressed.size() : data.size();
        raw_sizes[i] = data.size();
        filename_sizes[i] = filenames[i].size();
        header_offsets[i] = bytes_added_files;

        // Write all data to file

        // Signature
        out << (char)0x50 << (char)0x4b << (char)0x03 << (char)0x04;
        bytes_added_files += 4;
        // Version needed to extract (minimum)
        out << (char)0x14 << (char)0x00;
        bytes_added_files += 2;
        // General purpose flag
        out << (char)0x00 << (char)0x00;
        bytes_added_files += 2;
        // Compression method
        if (compression[i])
        {
            out << (char)0x08 << (char)0x00;
        }
        else
        {
            out << (char)0x00 << (char)0x00;
        }
        bytes_added_files += 2;
        // Last modification time
        out << ((char*)(&msdos_now))[0] << ((char*)(&msdos_now))[1];
        bytes_added_files += 2;
        // Last modification date
        out << ((char*)(&msdos_now))[2] << ((char*)(&msdos_now))[3];
        bytes_added_files += 2;
        // CRC-32 of raw data
        out << ((char*)crcs.data())[i * 4 + 0] << ((char*)crcs.data())[i * 4 + 1] << ((char*)crcs.data())[i * 4 + 2] << ((char*)crcs.data())[i * 4 + 3];
        bytes_added_files += 4;
        // Compressed size
        out << ((char*)compressed_sizes.data())[i * 4 + 0] << ((char*)compressed_sizes.data())[i * 4 + 1] << ((char*)compressed_sizes.data())[i * 4 + 2] << ((char*)compressed_sizes.data())[i * 4 + 3];
        bytes_added_files += 4;
        // Uncompressed size
        out << ((char*)raw_sizes.data())[i * 4 + 0] << ((char*)raw_sizes.data())[i * 4 + 1] << ((char*)raw_sizes.data())[i * 4 + 2] << ((char*)raw_sizes.data())[i * 4 + 3];
        bytes_added_files += 4;
        // File name length
        out << ((char*)filename_sizes.data())[i * 2 + 0] << ((char*)filename_sizes.data())[i * 2 + 1];
        bytes_added_files += 2;
        // Extra field length
        out << (char)0x00 << (char)0x00;
        bytes_added_files += 2;
        // File name
        out << filenames[i];
        bytes_added_files += filename_sizes[i];
        // File Content
        if (compression[i])
        {
            out.write((char*)compressed.data(), compressed.size());
            bytes_added_files += compressed.size();
        }
        else
        {
            out.write((char*)data.data(), data.size());
            bytes_added_files += data.size();
        }
    }

    // Central directory file header
    for (int i = 0; i < inputs.size(); i++)
    {
        // Signature
        out << (char)0x50 << (char)0x4b << (char)0x01 << (char)0x02;
        bytes_added_central_directory += 4;
        // Version made by
        out << (char)0x14 << (char)0x00;
        bytes_added_central_directory += 2;
        // Version needed to extract (minimum)
        out << (char)0x14 << (char)0x00;
        bytes_added_central_directory += 2;
        // General purpose flag
        out << (char)0x00 << (char)0x00;
        bytes_added_central_directory += 2;
        // Compression method
        if (compression[i])
        {
            out << (char)0x08 << (char)0x00;
        }
        else
        {
            out << (char)0x00 << (char)0x00;
        }
        bytes_added_central_directory += 2;
        // Last modification time
        out << ((char*)(&msdos_now))[0] << ((char*)(&msdos_now))[1];
        bytes_added_central_directory += 2;
        // Last modification date
        out << ((char*)(&msdos_now))[2] << ((char*)(&msdos_now))[3];
        bytes_added_central_directory += 2;
        // CRC-32 of raw data
        out << ((char*)crcs.data())[i * 4 + 0] << ((char*)crcs.data())[i * 4 + 1] << ((char*)crcs.data())[i * 4 + 2] << ((char*)crcs.data())[i * 4 + 3];
        bytes_added_central_directory += 4;
        // Compressed size
        out << ((char*)compressed_sizes.data())[i * 4 + 0] << ((char*)compressed_sizes.data())[i * 4 + 1] << ((char*)compressed_sizes.data())[i * 4 + 2] << ((char*)compressed_sizes.data())[i * 4 + 3];
        bytes_added_central_directory += 4;
        // Uncompressed size
        out << ((char*)raw_sizes.data())[i * 4 + 0] << ((char*)raw_sizes.data())[i * 4 + 1] << ((char*)raw_sizes.data())[i * 4 + 2] << ((char*)raw_sizes.data())[i * 4 + 3];
        bytes_added_central_directory += 4;
        // File name length
        out << ((char*)filename_sizes.data())[i * 2 + 0] << ((char*)filename_sizes.data())[i * 2 + 1];
        bytes_added_central_directory += 2;
        // Extra field length
        out << (char)0x00 << (char)0x00;
        bytes_added_central_directory += 2;
        // File comment length
        out << (char)0x00 << (char)0x00;
        bytes_added_central_directory += 2;
        // Disk number where file starts
        out << (char)0x00 << (char)0x00;
        bytes_added_central_directory += 2;
        // Internal file attributes
        out << (char)0x01 << (char)0x00;
        bytes_added_central_directory += 2;
        // External file attributes
        out << (char)0x20 << (char)0x00 << (char)0x00 << (char)0x00;
        bytes_added_central_directory += 4;
        // Relative offset of local file header
        out << ((char*)header_offsets.data())[i * 4 + 0] << ((char*)header_offsets.data())[i * 4 + 1] << ((char*)header_offsets.data())[i * 4 + 2] << ((char*)header_offsets.data())[i * 4 + 3];
        bytes_added_central_directory += 4;
        // File name
        out << filenames[i];
        bytes_added_central_directory += filename_sizes[i];
    }

    // End of central directory record
    // Signature
    out << (char)0x50 << (char)0x4b << (char)0x05 << (char)0x06;
    // Number of this disk
    out << (char)0x00 << (char)0x00;
    // Disk where central directory starts
    out << (char)0x00 << (char)0x00;
    // Number of central directory records on this disk
    out << ((char*)(&number_of_records))[0] << ((char*)(&number_of_records))[1];
    // Total number of central directory records
    out << ((char*)(&number_of_records))[0] << ((char*)(&number_of_records))[1];
    // Size of central directory (51x2)
    out << ((char*)(&bytes_added_central_directory))[0] << ((char*)(&bytes_added_central_directory))[1] << ((char*)(&bytes_added_central_directory))[2] << ((char*)(&bytes_added_central_directory))[3];
    // Offset of start of central directory
    out << ((char*)(&bytes_added_files))[0] << ((char*)(&bytes_added_files))[1] << ((char*)(&bytes_added_files))[2] << ((char*)(&bytes_added_files))[3];
    // Comment length
    out << (char)0x00 << (char)0x00;

    out.close();
}