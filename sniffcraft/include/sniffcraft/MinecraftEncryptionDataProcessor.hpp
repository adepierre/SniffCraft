#pragma once

#ifdef USE_ENCRYPTION
#include <memory>

#include "sniffcraft/DataProcessor.hpp"

namespace Botcraft
{
	class AESEncrypter;
}

class MinecraftEncryptionDataProcessor : public DataProcessor
{
public:
	MinecraftEncryptionDataProcessor(std::unique_ptr<Botcraft::AESEncrypter>& encrypter_);
	virtual ~MinecraftEncryptionDataProcessor();

	virtual std::vector<unsigned char> ProcessIncomingData(const std::vector<unsigned char>& data) const override;
	virtual std::vector<unsigned char> ProcessOutgoingData(const std::vector<unsigned char>& data) const override;

private:
	std::unique_ptr<Botcraft::AESEncrypter> encrypter;
};
#endif