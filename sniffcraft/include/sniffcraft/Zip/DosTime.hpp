#pragma once
#include <chrono>

class DosTime
{
public:
    static const unsigned int Now()
    {
        auto now = std::chrono::system_clock::now();
        time_t tt = std::chrono::system_clock::to_time_t(now);
        tm local_tm = *localtime(&tt);

        int year = local_tm.tm_year + 1900;
        int month = local_tm.tm_mon + 1;
        int day = local_tm.tm_mday;
        int hour = local_tm.tm_hour;
        int min = local_tm.tm_min;
        int sec = local_tm.tm_sec;

        return ((year - 1980) << 25)
            | (month << 21)
            | (day << 16)
            | (hour << 11)
            | (min << 5)
            | (sec >> 1);
    }
};