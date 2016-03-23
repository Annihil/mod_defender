#ifndef MOD_DEFENDER_UTIL_H
#define MOD_DEFENDER_UTIL_H

#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <sys/types.h>
#include <unistd.h>

using std::chrono::system_clock;
using namespace std::chrono;
using std::vector;
using std::string;
using std::stringstream;
using std::endl;
using std::istringstream;
using std::pair;

enum DEF_LOGLEVEL {
    DEFLOG_EMERG = 0,
    DEFLOG_ALERT,
    DEFLOG_CRIT,
    DEFLOG_ERROR,
    DEFLOG_WARN,
    DEFLOG_NOTICE,
    DEFLOG_INFO,
    DEFLOG_DEBUG
};

static const char *logLevels[] = {
        "emerg",
        "alert",
        "crit",
        "error",
        "warn",
        "notice",
        "info",
        "debug",
        NULL
};

class Util {

public:
    static string &ltrim(string &s) { // trim from start
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
        return s;
    }

    static string &rtrim(string &s) { // trim from end
        s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
        return s;
    }

    static string &trim(string &s) { // trim from both ends
        return ltrim(rtrim(s));
    }

    static vector<string> split(string &s, char delim);
    static pair<string, string> splitAtFirst(const string &s, string delim);
    static vector<int> splitToInt(string &s, char delimiter);
    static int countSubstring(const string &str, const string &sub) {
        if (sub.length() == 0) return 0;
        int count = 0;
        for (size_t offset = str.find(sub); offset != std::string::npos;
             offset = str.find(sub, offset + sub.length())) {
            ++count;
        }
        return count;
    }
    static string apacheTimeFmt();
    static string formatLog(DEF_LOGLEVEL loglevel, char *client);
};


#endif //MOD_DEFENDER_UTIL_H
