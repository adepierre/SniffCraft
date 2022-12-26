#ifdef USE_ENCRYPTION
#include <botcraft/Network/AESEncrypter.hpp>

#include "sniffcraft/MinecraftEncryptionDataProcessor.hpp"

MinecraftEncryptionDataProcessor::MinecraftEncryptionDataProcessor(std::unique_ptr<Botcraft::AESEncrypter>& encrypter_)
{
    encrypter = std::move(encrypter_);
}

MinecraftEncryptionDataProcessor::~MinecraftEncryptionDataProcessor()
{
}

std::vector<unsigned char> MinecraftEncryptionDataProcessor::ProcessIncomingData(const std::vector<unsigned char>& data) const
{
    return encrypter->Decrypt(data);
}

std::vector<unsigned char> MinecraftEncryptionDataProcessor::ProcessOutgoingData(const std::vector<unsigned char>& data) const
{
    return encrypter->Encrypt(data);
}
#endif
