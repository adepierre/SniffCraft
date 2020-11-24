#pragma once

#include "protocolCraft/NetworkType.hpp"

using namespace ProtocolCraft;

class DNSResourceRecord : public NetworkType
{
public:
    const std::vector<std::string>& GetNameLabels() const
    {
        return name_labels;
    }

    const unsigned short GetTypeCode() const
    {
        return type_code;
    }

    const unsigned short GetClassCode() const
    {
        return class_code;
    }

    const unsigned int GetTTL() const
    {
        return ttl;
    }

    const unsigned short GetRDLength() const
    {
        return rd_length;
    }

    const std::vector<unsigned char>& GetRData() const
    {
        return rdata;
    }


    void SetNameLabels(const std::vector<std::string>& name_labels_)
    {
        name_labels = name_labels_;
    }

    void SetTypeCode(const unsigned short type_code_)
    {
        type_code = type_code_;
    }

    void SetClassCode(const unsigned short class_code_)
    {
        class_code = class_code_;
    }

    void SetTTL(const unsigned int ttl_)
    {
        ttl = ttl_;
    }

    void SetRDLength(const unsigned short rd_length_)
    {
        rd_length = rd_length_;
    }

    void SetRData(const std::vector<unsigned char>& rdata_)
    {
        rdata = rdata_;
    }

protected:
    virtual void ReadImpl(ReadIterator& iter, size_t& length) override
    {
        name_labels = std::vector<std::string>();
        bool done = false;

        while (!done)
        {
            unsigned char first_byte = ReadData<unsigned char>(iter, length);
            // Check if this is a pointer
            if (first_byte >> 6 == 0x03)
            {
                unsigned char second_byte = ReadData<unsigned char>(iter, length);
                // we actually don't need the value pointed in this application
                name_labels.push_back("unresolved pointer");
                done = true;
            }
            else if (first_byte == 0x00)
            {
                done = true;
            }
            else
            {
                name_labels.push_back(ReadRawString(iter, length, first_byte));
            }
        }

        type_code = ReadData<unsigned short>(iter, length);
        class_code = ReadData<unsigned short>(iter, length);
        ttl = ReadData<unsigned int>(iter, length);
        rd_length = ReadData<unsigned short>(iter, length);
        rdata = ReadByteArray(iter, length, rd_length);
    }

    virtual void WriteImpl(WriteContainer& container) const override
    {
        // We don't support compression for write (it shouldn't been called in this program anyway)
        for (int i = 0; i < name_labels.size(); ++i)
        {
            WriteData<unsigned char>(name_labels[i].size(), container);
            WriteRawString(name_labels[i], container);
        }
        WriteData<unsigned char>(0, container);

        WriteData<unsigned short>(type_code, container);
        WriteData<unsigned short>(class_code, container);
        WriteData<unsigned int>(ttl, container);
        WriteData<unsigned short>(rd_length, container);
        WriteByteArray(rdata, container);
    }

    virtual const picojson::value SerializeImpl() const override
    {
        picojson::value val(picojson::object_type, false);
        picojson::object& object = val.get<picojson::object>();
        std::string name = "";
        for (int i = 0; i < name_labels.size(); ++i)
        {
            name += name_labels[i] + ".";
        }
        object["identification"] = picojson::value(name);

        object["type_code"] = picojson::value((double)type_code);
        object["class_code"] = picojson::value((double)class_code);
        object["ttl"] = picojson::value((double)ttl);
        object["rd_length"] = picojson::value((double)rd_length);


        object["rdata"] = picojson::value(picojson::array_type, false);
        picojson::array& array = object["rdata"].get<picojson::array>();
        for (int i = 0; i < rd_length; ++i)
        {
            array.push_back(picojson::value((double)rdata[i]));
        }

        return val;
    }

private:
    std::vector<std::string> name_labels;
    unsigned short type_code;
    unsigned short class_code;
    unsigned int ttl;
    unsigned short rd_length;
    std::vector<unsigned char> rdata;
};
