#pragma once

#include "protocolCraft/NetworkType.hpp"

using namespace ProtocolCraft;

class DNSQuestion : public NetworkType
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

protected:
    virtual void ReadImpl(ReadIterator& iter, size_t& length) override
    {
        name_labels = std::vector<std::string>();
        std::string label;
        unsigned char label_len = ReadData<unsigned char>(iter, length);
        while (label_len != 0)
        {
            label = ReadRawString(iter, length, label_len);
            label_len = ReadData<unsigned char>(iter, length);
            name_labels.push_back(label);
        }

        type_code = ReadData<unsigned short>(iter, length);
        class_code = ReadData<unsigned short>(iter, length);
    }

    virtual void WriteImpl(WriteContainer& container) const override
    {
        for (int i = 0; i < name_labels.size(); ++i)
        {
            WriteData<unsigned char>(name_labels[i].size(), container);
            WriteRawString(name_labels[i], container);
        }
        WriteData<unsigned char>(0, container);

        WriteData<unsigned short>(type_code, container);
        WriteData<unsigned short>(class_code, container);
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

        return val;
    }

private:
    std::vector<std::string> name_labels;
    unsigned short type_code;
    unsigned short class_code;
};