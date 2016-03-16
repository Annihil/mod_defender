#ifndef CAPPLICATION_HPP
#define CAPPLICATION_HPP

<<<<<<< HEAD
#include "mod_defender.hpp"

class CApplication {
private:
    request_rec*    m_pRequestRec;

public:
    CApplication(request_rec* inpRequestRec):
            m_pRequestRec(inpRequestRec)
    {}

    int RunHandler();
=======
#include <map>
#include <vector>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <chrono>
#include <httpd.h>
#include <unordered_map>
#include "NxParser.h"
#include "mod_defender.hpp"

using std::chrono::system_clock;
using std::pair;
using std::vector;
using std::string;
using std::cerr;
using std::stringstream;
using std::endl;
using std::flush;
using std::regex_match;
using std::unordered_map;

class CApplication {
private:
    request_rec* r;
    server_config_t* scfg;
    apr_pool_t* pool;
    stringstream matchVars;
    unsigned int rulesMatchedCount = 0;
    vector<pair<const char *, const char *>> headers;
    vector<pair<const char *, const char *>> args;
    vector<pair<const char *, const char *>> body;
    unordered_map<string, check_rule_t> checkRules;
    unordered_map<string, int> matchScores;

    bool block = false;
    bool drop = false;
    bool allow = false;
    bool log = false;

public:
    CApplication(request_rec* rec, server_config_t* scfg);
    static int storeTable(void*, const char*, const char*);
    void readPost();
    int runHandler();
<<<<<<< HEAD
<<<<<<< HEAD
    void checkVar(const char *varName, const char *value, const char *zone);
    void checkVector(const char *zone, vector<pair<const char *, const char *>> &v);
<<<<<<< HEAD
<<<<<<< HEAD
    void formatAttack(const nxrule_t &rule, string zone, string varname);
>>>>>>> 5eee329... naxsi core rules parser
=======
    string formatMatch(const nxrule_t &rule, string zone, string varName);
>>>>>>> fd0f819... scoring system
=======
    string formatMatch(const main_rule_t &rule, string zone, string varName);
    void applyCheckRule(const main_rule_t &rule, int matchCount);
>>>>>>> 40a8641... enhanced conf parsing
=======
    string formatMatch(const main_rule_t &rule, const char *zone, const char *varName);
    void applyCheckRule(const main_rule_t &rule, int matchCount);
    void checkVector(const char *zone, vector<pair<const char *, const char *>> &v, const main_rule_t &rule);
    void checkVar(const char *zone, const char *varName, const char *value, const main_rule_t &rule);
=======
    string formatMatch(const http_rule_t &rule, const char *zone, const char *varName);
    void applyCheckRule(const http_rule_t &rule, int matchCount);
    void checkVector(const char *zone, vector<pair<const char *, const char *>> &v, const http_rule_t &rule);
    void checkVar(const char *zone, const char *varName, const char *value, const http_rule_t &rule);
>>>>>>> 4164dbd... wl hashtables system
    void applyCheckRuleAction(const rule_action_t &action);
>>>>>>> 71479aa... added url zone checking
};

#endif /* CAPPLICATION_HPP */

