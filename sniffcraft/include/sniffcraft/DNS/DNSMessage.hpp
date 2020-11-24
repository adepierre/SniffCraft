#pragma once

#include "protocolCraft/NetworkType.hpp"

#include "sniffcraft/DNS/DNSQuestion.hpp"
#include "sniffcraft/DNS/DNSResourceRecord.hpp"

using namespace ProtocolCraft;

class DNSMessage : public NetworkType
{
public:
    const std::vector<unsigned char>& GetIdentification() const
    {
        return identification;
    }

    const char GetFlagQR() const
    {
        return qr;
    }

    const char GetFlagOPCode() const
    {
        return opcode;
    }

    const char GetFlagAA() const
    {
        return aa;
    }

    const char GetFlagTC() const
    {
        return tc;
    }

    const char GetFlagRD() const
    {
        return rd;
    }

    const char GetFlagRA() const
    {
        return ra;
    }

    const char GetFlagZ() const
    {
        return z;
    }

    const char GetFlagRCode() const
    {
        return rcode;
    }

    const short GetNumberQuestion() const
    {
        return number_question;
    }

    const short GetNumberAnswer() const
    {
        return number_answer;
    }

    const short GetNumberAuthority() const
    {
        return number_authority;
    }

    const short GetNumberAdditionalRR() const
    {
        return number_additional_rr;
    }

    const std::vector<DNSQuestion>& GetQuestions() const
    {
        return questions;
    }

    const std::vector<DNSResourceRecord>& GetAnswers() const
    {
        return answers;
    }

    const std::vector<DNSResourceRecord>& GetAuthorities() const
    {
        return authorities;
    }

    const std::vector<DNSResourceRecord>& GetAdditionals() const
    {
        return additionals;
    }


    void SetIdentification(const std::vector<unsigned char>& identification_)
    {
        identification = identification_;
    }

    void SetFlagQR(const char qr_)
    {
        qr = qr_;
    }

    void SetFlagOPCode(const char opcode_)
    {
        opcode = opcode_;
    }

    void SetFlagAA(const char aa_)
    {
        aa = aa_;
    }

    void SetFlagTC(const char tc_)
    {
        tc = tc_;
    }

    void SetFlagRD(const char rd_)
    {
        rd = rd_;
    }

    void SetFlagRA(const char ra_)
    {
        ra = ra_;
    }

    void SetFlagZ(const char z_)
    {
        z = z_;
    }

    void SetFlagRCode(const char rcode_)
    {
        rcode = rcode_;
    }

    void SetNumberQuestion(const short number_question_)
    {
        number_question = number_question_;
    }

    void SetNumberAnswer(const short number_answer_)
    {
        number_answer = number_answer_;
    }

    void SetNumberAuthority(const short number_authority_)
    {
        number_authority = number_authority_;
    }

    void SetNumberAdditionalRR(const short number_additional_rr_)
    {
        number_additional_rr = number_additional_rr_;
    }

    void SetQuestions(const std::vector<DNSQuestion>& questions_)
    {
        questions = questions_;
    }

    void SetAnswers(const std::vector<DNSResourceRecord>& answers_)
    {
        answers = answers_;
    }

    void SetAuthorities(const std::vector<DNSResourceRecord>& authorities_)
    {
        authorities = authorities_;
    }

    void SetAdditionals(const std::vector<DNSResourceRecord>& additionals_)
    {
        additionals = additionals_;
    }

protected:
    virtual void ReadImpl(ReadIterator& iter, size_t& length) override
    {
        identification = ReadByteArray(iter, length, 2);
        char flags0 = ReadData<char>(iter, length);
        qr = (flags0 >> 7) & 0x01;
        opcode = (flags0 >> 3) & 0x0F;
        aa = (flags0 >> 2) & 0x01;
        tc = (flags0 >> 1) & 0x01;
        rd = flags0 & 0x01;

        char flags1 = ReadData<char>(iter, length);
        ra = (flags1 >> 7) & 0x01;
        z = (flags1 >> 4) & 0x07;
        rcode = flags1 & 0x0F;

        number_question = ReadData<short>(iter, length);
        number_answer = ReadData<short>(iter, length);
        number_authority = ReadData<short>(iter, length);
        number_additional_rr = ReadData<short>(iter, length);

        questions = std::vector<DNSQuestion>(number_question);
        for (int i = 0; i < number_question; ++i)
        {
            questions[i].Read(iter, length);
        }

        answers = std::vector<DNSResourceRecord>(number_answer);
        for (int i = 0; i < number_answer; ++i)
        {
            answers[i].Read(iter, length);
        }

        authorities = std::vector<DNSResourceRecord>(number_authority);
        for (int i = 0; i < number_authority; ++i)
        {
            authorities[i].Read(iter, length);
        }

        additionals = std::vector<DNSResourceRecord>(number_additional_rr);
        for (int i = 0; i < number_additional_rr; ++i)
        {
            additionals[i].Read(iter, length);
        }

    }

    virtual void WriteImpl(WriteContainer& container) const override
    {
        WriteByteArray(identification, container);

        char flags0 = (qr << 7) | (opcode << 3) | (aa << 2) | (tc << 1) | rd;
        WriteData<char>(flags0, container);

        char flags1 = (ra << 7) | (z << 4) | opcode;
        WriteData<char>(flags1, container);

        WriteData<short>(number_question, container);
        WriteData<short>(number_answer, container);
        WriteData<short>(number_authority, container);
        WriteData<short>(number_additional_rr, container);

        for (int i = 0; i < questions.size(); ++i)
        {
            questions[i].Write(container);
        }

        for (int i = 0; i < answers.size(); ++i)
        {
            answers[i].Write(container);
        }

        for (int i = 0; i < authorities.size(); ++i)
        {
            authorities[i].Write(container);
        }

        for (int i = 0; i < additionals.size(); ++i)
        {
            additionals[i].Write(container);
        }
    }

    virtual const picojson::value SerializeImpl() const override
    {
        picojson::value val(picojson::object_type, false);
        picojson::object& object = val.get<picojson::object>();

        object["qr"] = picojson::value((double)qr);
        object["opcode"] = picojson::value((double)opcode);
        object["aa"] = picojson::value((double)aa);
        object["tc"] = picojson::value((double)tc);
        object["rd"] = picojson::value((double)rd);
        object["ra"] = picojson::value((double)ra);
        object["z"] = picojson::value((double)z);
        object["rcode"] = picojson::value((double)rcode);

        object["number_question"] = picojson::value((double)number_question);
        object["number_answer"] = picojson::value((double)number_answer);
        object["number_authority"] = picojson::value((double)number_authority);
        object["number_additional_rr"] = picojson::value((double)number_additional_rr);

        object["questions"] = picojson::value(picojson::array_type, false);
        picojson::array& array = object["questions"].get<picojson::array>();
        for (int i = 0; i < number_question; ++i)
        {
            array.push_back(questions[i].Serialize());
        }

        object["answers"] = picojson::value(picojson::array_type, false);
        array = object["answers"].get<picojson::array>();
        for (int i = 0; i < number_answer; ++i)
        {
            array.push_back(answers[i].Serialize());
        }

        object["authorities"] = picojson::value(picojson::array_type, false);
        array = object["authorities"].get<picojson::array>();
        for (int i = 0; i < number_authority; ++i)
        {
            array.push_back(authorities[i].Serialize());
        }

        object["additionals"] = picojson::value(picojson::array_type, false);
        array = object["additionals"].get<picojson::array>();
        for (int i = 0; i < number_additional_rr; ++i)
        {
            array.push_back(additionals[i].Serialize());
        }

        return val;
    }

private:
    std::vector<unsigned char> identification;

    // Flags
    char qr;
    char opcode;
    char aa;
    char tc;
    char rd;
    char ra;
    char z;
    char rcode;


    short number_question;
    short number_answer;
    short number_authority;
    short number_additional_rr;

    std::vector<DNSQuestion> questions;
    std::vector<DNSResourceRecord> answers;
    std::vector<DNSResourceRecord> authorities;
    std::vector<DNSResourceRecord> additionals;

};