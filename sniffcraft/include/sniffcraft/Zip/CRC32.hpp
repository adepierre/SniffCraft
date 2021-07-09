#pragma once

#include <vector>
#include <string>

class CRC32
{
public:
	static const std::vector<unsigned int>& GetTable()
	{
		static std::vector<unsigned int> table;

		if (table.size() != 0)
		{
			return table;
		}

		const unsigned int polynomial = 0xEDB88320;
		table = std::vector<unsigned int>(256);

		for (unsigned int i = 0; i < 256; ++i)
		{
			unsigned int c = i;
			for (int j = 0; j < 8; ++j)
			{
				if (c & 1)
				{
					c = polynomial ^ (c >> 1);
				}
				else
				{
					c >>= 1;
				}
			}
			table[i] = c;
		}

		return table;
	}

	static const unsigned int Update(const unsigned int initial, const std::vector<unsigned char>& data)
	{
		const std::vector<unsigned int>& table = GetTable();
		unsigned int c = initial ^ 0xFFFFFFFF;
		for (int i = 0; i < data.size(); ++i)
		{
			c = table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
		}

		return c ^ 0xFFFFFFFF;
	}

};
