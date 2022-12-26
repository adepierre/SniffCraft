#pragma once

#include <vector>

class DataProcessor
{
public:
	DataProcessor() {};
	virtual ~DataProcessor() {};

	virtual std::vector<unsigned char> ProcessIncomingData(const std::vector<unsigned char>& data) const = 0;
	virtual std::vector<unsigned char> ProcessOutgoingData(const std::vector<unsigned char>& data) const = 0;
};
