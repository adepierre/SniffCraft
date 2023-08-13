#include "sniffcraft/Zip/ZeptoZip.hpp"
#include "sniffcraft/Zip/DosTime.hpp"
#include "sniffcraft/Compression.hpp"

#include <fstream>
#include <assert.h>

void ZeptoZip::CreateZipArchive(const std::string& outpath, const std::vector<std::string>& inputs, const std::vector<std::string>& filenames)
{
    // We assume inputs.size() == filenames.size()

    std::ofstream out_file(outpath, std::ios::out | std::ios::binary);
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
        filename_sizes[i] = filenames[i].size();
        header_offsets[i] = bytes_added_files;

        // Write all data to file

        // Signature
        out_file << (char)0x50 << (char)0x4b << (char)0x03 << (char)0x04;
        bytes_added_files += 4;
        // Version needed to extract (minimum)
        out_file << (char)0x14 << (char)0x00;
        bytes_added_files += 2;
        // General purpose flag
        out_file << (char)0x00 << (char)0x00;
        bytes_added_files += 2;
        // Compression method
        out_file << (char)0x08 << (char)0x00;
        bytes_added_files += 2;
        // Last modification time
        out_file << ((char*)(&msdos_now))[0] << ((char*)(&msdos_now))[1];
        bytes_added_files += 2;
        // Last modification date
        out_file << ((char*)(&msdos_now))[2] << ((char*)(&msdos_now))[3];
        bytes_added_files += 2;
        // CRC-32 of raw data
        const unsigned int crc_offset = bytes_added_files;
        out_file << (char)0x00 << (char)0x00 << (char)0x00 << (char)0x00; // temp value, will be set later
        bytes_added_files += 4;
        // Compressed size
        const unsigned int compressed_size_offset = bytes_added_files;
        out_file << (char)0x00 << (char)0x00 << (char)0x00 << (char)0x00; // temp value, will be set later
        bytes_added_files += 4;
        // Uncompressed size
        const unsigned int uncompressed_size_offset = bytes_added_files;
        out_file << (char)0x00 << (char)0x00 << (char)0x00 << (char)0x00; // temp value, will be set later
        bytes_added_files += 4;
        // File name length
        out_file << ((char*)filename_sizes.data())[i * 2 + 0] << ((char*)filename_sizes.data())[i * 2 + 1];
        bytes_added_files += 2;
        // Extra field length
        out_file << (char)0x00 << (char)0x00;
        bytes_added_files += 2;
        // File name
        out_file << filenames[i];
        bytes_added_files += filename_sizes[i];
        // File Content
        std::ifstream in_file(inputs[i], std::ios::binary);
        std::tuple<size_t, size_t, unsigned long> compression_output = CompressRawDeflateFile(in_file, out_file);
        in_file.close();
        raw_sizes[i] = std::get<0>(compression_output);
        compressed_sizes[i] = std::get<1>(compression_output);
        crcs[i] = std::get<2>(compression_output);
        bytes_added_files += compressed_sizes[i];

        // Replace temp values now that we have the correct ones
        out_file.seekp(crc_offset);
        out_file << ((char*)crcs.data())[i * 4 + 0] << ((char*)crcs.data())[i * 4 + 1] << ((char*)crcs.data())[i * 4 + 2] << ((char*)crcs.data())[i * 4 + 3];
        out_file.seekp(compressed_size_offset);
        out_file << ((char*)compressed_sizes.data())[i * 4 + 0] << ((char*)compressed_sizes.data())[i * 4 + 1] << ((char*)compressed_sizes.data())[i * 4 + 2] << ((char*)compressed_sizes.data())[i * 4 + 3];
        out_file.seekp(uncompressed_size_offset);
        out_file << ((char*)raw_sizes.data())[i * 4 + 0] << ((char*)raw_sizes.data())[i * 4 + 1] << ((char*)raw_sizes.data())[i * 4 + 2] << ((char*)raw_sizes.data())[i * 4 + 3];

        // Go back at the end of the file for the next file
        out_file.seekp(0, std::ios_base::end);
    }

    // Central directory file header
    for (int i = 0; i < inputs.size(); i++)
    {
        // Signature
        out_file << (char)0x50 << (char)0x4b << (char)0x01 << (char)0x02;
        bytes_added_central_directory += 4;
        // Version made by
        out_file << (char)0x14 << (char)0x00;
        bytes_added_central_directory += 2;
        // Version needed to extract (minimum)
        out_file << (char)0x14 << (char)0x00;
        bytes_added_central_directory += 2;
        // General purpose flag
        out_file << (char)0x00 << (char)0x00;
        bytes_added_central_directory += 2;
        // Compression method
        out_file << (char)0x08 << (char)0x00;
        bytes_added_central_directory += 2;
        // Last modification time
        out_file << ((char*)(&msdos_now))[0] << ((char*)(&msdos_now))[1];
        bytes_added_central_directory += 2;
        // Last modification date
        out_file << ((char*)(&msdos_now))[2] << ((char*)(&msdos_now))[3];
        bytes_added_central_directory += 2;
        // CRC-32 of raw data
        out_file << ((char*)crcs.data())[i * 4 + 0] << ((char*)crcs.data())[i * 4 + 1] << ((char*)crcs.data())[i * 4 + 2] << ((char*)crcs.data())[i * 4 + 3];
        bytes_added_central_directory += 4;
        // Compressed size
        out_file << ((char*)compressed_sizes.data())[i * 4 + 0] << ((char*)compressed_sizes.data())[i * 4 + 1] << ((char*)compressed_sizes.data())[i * 4 + 2] << ((char*)compressed_sizes.data())[i * 4 + 3];
        bytes_added_central_directory += 4;
        // Uncompressed size
        out_file << ((char*)raw_sizes.data())[i * 4 + 0] << ((char*)raw_sizes.data())[i * 4 + 1] << ((char*)raw_sizes.data())[i * 4 + 2] << ((char*)raw_sizes.data())[i * 4 + 3];
        bytes_added_central_directory += 4;
        // File name length
        out_file << ((char*)filename_sizes.data())[i * 2 + 0] << ((char*)filename_sizes.data())[i * 2 + 1];
        bytes_added_central_directory += 2;
        // Extra field length
        out_file << (char)0x00 << (char)0x00;
        bytes_added_central_directory += 2;
        // File comment length
        out_file << (char)0x00 << (char)0x00;
        bytes_added_central_directory += 2;
        // Disk number where file starts
        out_file << (char)0x00 << (char)0x00;
        bytes_added_central_directory += 2;
        // Internal file attributes
        out_file << (char)0x01 << (char)0x00;
        bytes_added_central_directory += 2;
        // External file attributes
        out_file << (char)0x20 << (char)0x00 << (char)0x00 << (char)0x00;
        bytes_added_central_directory += 4;
        // Relative offset of local file header
        out_file << ((char*)header_offsets.data())[i * 4 + 0] << ((char*)header_offsets.data())[i * 4 + 1] << ((char*)header_offsets.data())[i * 4 + 2] << ((char*)header_offsets.data())[i * 4 + 3];
        bytes_added_central_directory += 4;
        // File name
        out_file << filenames[i];
        bytes_added_central_directory += filename_sizes[i];
    }

    // End of central directory record
    // Signature
    out_file << (char)0x50 << (char)0x4b << (char)0x05 << (char)0x06;
    // Number of this disk
    out_file << (char)0x00 << (char)0x00;
    // Disk where central directory starts
    out_file << (char)0x00 << (char)0x00;
    // Number of central directory records on this disk
    out_file << ((char*)(&number_of_records))[0] << ((char*)(&number_of_records))[1];
    // Total number of central directory records
    out_file << ((char*)(&number_of_records))[0] << ((char*)(&number_of_records))[1];
    // Size of central directory (51x2)
    out_file << ((char*)(&bytes_added_central_directory))[0] << ((char*)(&bytes_added_central_directory))[1] << ((char*)(&bytes_added_central_directory))[2] << ((char*)(&bytes_added_central_directory))[3];
    // Offset of start of central directory
    out_file << ((char*)(&bytes_added_files))[0] << ((char*)(&bytes_added_files))[1] << ((char*)(&bytes_added_files))[2] << ((char*)(&bytes_added_files))[3];
    // Comment length
    out_file << (char)0x00 << (char)0x00;

    out_file.close();
}
