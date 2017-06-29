/*                       _        _       __                _
 *   _ __ ___   ___   __| |    __| | ___ / _| ___ _ __   __| | ___ _ __
 *  | '_ ` _ \ / _ \ / _` |   / _` |/ _ \ |_ / _ \ '_ \ / _` |/ _ \ '__|
 *  | | | | | | (_) | (_| |  | (_| |  __/  _|  __/ | | | (_| |  __/ |
 *  |_| |_| |_|\___/ \__,_|___\__,_|\___|_|  \___|_| |_|\__,_|\___|_|
 *                       |_____|
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */

#include "RuntimeScanner.hpp"
#include "libinjection/libinjection_sqli.h"
#include "libinjection/libinjection.h"

void RuntimeScanner::applyRuleMatch(const http_rule_t &rule, unsigned long nbMatch, MATCH_ZONE zone, const string &name,
                                    const string &value, bool targetName) {
    if (logLevel >= LOG_LVL_NOTICE) {
        stringstream errlog;
        errlog << formatLog(LOG_LVL_NOTICE, clientIp);
        errlog << KRED "⚠ Rule #" << rule.id << " ";
        errlog << "(" << rule.logMsg << ") ";
        errlog << "matched " << nbMatch << " times ";
        if (targetName)
            errlog << "in name ";
        errlog << "at " << match_zones[zone] << " ";
        errlog << name.substr(0, 128) << (name.size() > 128 ? "..." : "");
        if (!value.empty())
            errlog << ":" << value.substr(0, 256) << (value.size() > 256 ? "..." : "");
        errlog << " ";
        if (rule.action != ALLOW)
            errlog << actions[rule.action] << " ";
        if (rule.action == BLOCK && learning)
            errlog << "(learning)";
        errlog << KNRM << endl;
        streamToFile(errlog, errorLogFile);
    }
    applyRuleAction(rule.action);

    if (rulesMatchedCount > 0)
        matchVars << "&";
    matchVars << "zone" << rulesMatchedCount << "=" << match_zones[zone] << "&";
    matchVars << "id" << rulesMatchedCount << "=" << rule.id << "&";
    matchVars << "var_name" << rulesMatchedCount << "=" << name;

    if (learningJSONLogFile) {
        if (rulesMatchedCount > 0)
            jsonMatchVars << ",";
        jsonMatchVars << "{\"zone\":\"" << match_zones[zone] << "\",";
        jsonMatchVars << "\"id\":" << rule.id << ",";
        jsonMatchVars << "\"var_name\":\"" << escapeQuotes(name) << "\"";
        if (extensiveLearning)
            jsonMatchVars << ",\"content\":\"" << escapeQuotes(value) << "\"";
        jsonMatchVars << "}";
    }

    writeExtensiveLog(rule, zone, name, value, targetName);

    rulesMatchedCount++;
}

void RuntimeScanner::applyRuleAction(const rule_action_t &rule_action) {
    if (rule_action == BLOCK)
        block = true;
    else if (rule_action == DROP)
        drop = true;
    else if (rule_action == LOG)
        log = true;
}

void RuntimeScanner::applyCheckRule(const http_rule_t &rule, unsigned long nbMatch, const string &name,
                                    const string &value, MATCH_ZONE zone, bool targetName) {
    if (parser.isRuleWhitelisted(rule, uri, name, zone, targetName)) {
        if (logLevel >= LOG_LVL_NOTICE) {
            stringstream errlog;
            errlog << formatLog(LOG_LVL_NOTICE, clientIp);
            errlog << KGRN "✓ Rule #" << rule.id << " ";
            errlog << "(" << rule.logMsg << ") ";
            errlog << "whitelisted ";
            if (targetName)
                errlog << "in name ";
            errlog << "at " << match_zones[zone] << " " << name << ":" << value << KNRM << endl;
            streamToFile(errlog, errorLogFile);
        }
        return;
    }
    // negative rule case
    if (nbMatch == 0)
        nbMatch = 1;

    applyRuleMatch(rule, nbMatch, zone, name, value, targetName);

    stringstream errlog;
    for (const pair<string, unsigned long> &tagScore : rule.scores) {
        bool matched = false;
        int &score = matchScores[tagScore.first];
        score += tagScore.second * nbMatch;

        if (logLevel >= LOG_LVL_NOTICE) {
            errlog << formatLog(LOG_LVL_NOTICE, clientIp);
            errlog << KYEL "→ Score " << tagScore.first << " = " << score << " ";
        }
        check_rule_t &checkRule = parser.checkRules[tagScore.first];
        if (checkRule.comparator == SUP_OR_EQUAL)
            matched = (score >= checkRule.limit);
        else if (checkRule.comparator == SUP)
            matched = (score > checkRule.limit);
        else if (checkRule.comparator <= INF_OR_EQUAL)
            matched = (score <= checkRule.limit);
        else if (checkRule.comparator < INF)
            matched = (score < checkRule.limit);

        if (matched) {
            applyRuleAction(checkRule.action);
            if (logLevel >= LOG_LVL_NOTICE && checkRule.action != ALLOW) {
                errlog << actions[checkRule.action] << " "
                       << (learning && checkRule.action == BLOCK ? "(learning)" : "");
            }
        }
        if (logLevel >= LOG_LVL_NOTICE)
            errlog << KNRM << endl;
    }

    if (logLevel >= LOG_LVL_NOTICE)
        streamToFile(errlog, errorLogFile);
}

bool RuntimeScanner::processRuleBuffer(const string &str, const http_rule_t &rl, unsigned long &nbMatch) {
    if (!rl.br.active || str.empty())
        return false;
    DEBUG_RUNTIME_PR("[" << str);
    nbMatch = 0;
    if (rl.br.match_type == STR) {
        DEBUG_RUNTIME_PR(" ? " << rl.br.str << "] ");
//        nbMatch = countSubstring(str, rl.br.str);
//        nbMatch = countSubstring(str.c_str(), str.size(), rl.br.str.c_str(), rl.br.str.size());
        nbMatch = countSubstring(str.c_str(), rl.br.str.c_str(), rl.br.str.size());

        if (nbMatch > 0) {
            DEBUG_RUNTIME_PR("matched " << endl);
            return !rl.br.negative;
        } else {
            return rl.br.negative;
        }
    } else if (rl.br.match_type == RX) {
        DEBUG_RUNTIME_PR(" ? <regex>] ");
        nbMatch = (unsigned long) distance(sregex_iterator(str.begin(), str.end(), rl.br.rx), sregex_iterator());
        if (nbMatch > 0) {
            DEBUG_RUNTIME_PR("matched " << endl);
            return !rl.br.negative;
        } else {
            return rl.br.negative;
        }
    } else if (rl.br.match_type == LIBINJ_SQL) {
        DEBUG_RUNTIME_PR(" ? LIBINJ_SQL] ");
        struct libinjection_sqli_state state;
        libinjection_sqli_init(&state, str.c_str(), str.size(), FLAG_NONE);
        if (libinjection_is_sqli(&state))
            return true;
    } else if (rl.br.match_type == LIBINJ_XSS) {
        DEBUG_RUNTIME_PR(" ? LIBINJ_XSS] ");
        if (libinjection_xss(str.c_str(), str.size()))
            return true;
    }
    return false;
}

void RuntimeScanner::basestrRuleset(MATCH_ZONE zone, const string &name, const string &value,
                                    const vector<http_rule_t> &rules) {
    if (libinjSQL || libinjXSS)
        checkLibInjection(zone, name, value);

    unsigned long nbMatch = 0;
    for (int i = 0; i < rules.size() && ((!block || learning) && !drop); i++) {
        const http_rule_t &rule = rules[i];
        DEBUG_RUNTIME_BRS(match_zones[zone] << ":#" << rule.id << " ");

        /* does the rule have a custom location ? custom location means checking only on a specific argument */
        if (!name.empty() && rule.br.customLocation) {
            DEBUG_RUNTIME_BRS("loc ");
            /* for each custom location */
            for (const custom_rule_location_t &loc : rule.br.customLocations) {
                /* check if the custom location zone match with the current zone (enhancement) */
                if (!((loc.bodyVar && zone == BODY) || (loc.argsVar && zone == ARGS) ||
                      (loc.headersVar && zone == HEADERS) || (loc.specificUrl && zone == URL))) {
                    DEBUG_RUNTIME_BRS("loc-zone-mismatch ");
                    continue;
                }
                /* if the name are the same, check */
                if (!loc.target.empty() && name == loc.target) {
                    DEBUG_RUNTIME_BRS(loc.target << " ");
                    /* match rule against var content, */
                    if (processRuleBuffer(value, rule, nbMatch)) {
                        applyCheckRule(rule, nbMatch, name, value, zone, false);
                    }

                    if (!rule.br.negative) {
                        /* match rule against var name, */
                        if (processRuleBuffer(name, rule, nbMatch)) {
                            /* if our rule matched, apply effects (score etc.) */
                            applyCheckRule(rule, nbMatch, name, value, zone, true);
                        }
                    }
                }
            }
        }

        /*
        ** check against the rule if the current zone is matching
        ** the zone the rule is meant to be check against
        */
        if ((zone == HEADERS && rule.br.headersMz) || (zone == URL && rule.br.urlMz) ||
            (zone == ARGS && rule.br.argsMz) || (zone == BODY && rule.br.bodyMz) ||
            (zone == FILE_EXT && rule.br.fileExtMz)) {
            DEBUG_RUNTIME_BRS("zone ");
            /* check the rule against the value*/
            if (processRuleBuffer(value, rule, nbMatch)) {
                /* if our rule matched, apply effects (score etc.) */
                applyCheckRule(rule, nbMatch, name, value, zone, false);
            }

            if (!rule.br.negative) {
                /* check the rule against the name */
                if (processRuleBuffer(name, rule, nbMatch)) {
                    /* if our rule matched, apply effects (score etc.) */
                    applyCheckRule(rule, nbMatch, name, value, zone, true);
                }
            }
        }
        DEBUG_RUNTIME_BRS("done" << endl);
    }
}

void RuntimeScanner::checkLibInjection(MATCH_ZONE zone, const string &name, const string &value) {
    if (value.empty() && name.empty())
        return;

    if (libinjSQL) {
        struct libinjection_sqli_state state;

        if (!value.empty()) {
            libinjection_sqli_init(&state, value.c_str(), value.size(), FLAG_NONE);

            if (libinjection_is_sqli(&state)) {
                parser.libsqliRule.logMsg = state.fingerprint;
                applyCheckRule(parser.libsqliRule, 1, name, value, zone, false);
            }
        }

        if (!name.empty()) {
            libinjection_sqli_init(&state, name.c_str(), name.size(), FLAG_NONE);

            if (libinjection_is_sqli(&state)) {
                parser.libsqliRule.logMsg = state.fingerprint;
                applyCheckRule(parser.libsqliRule, 1, name, value, zone, true);
            }
        }
    }

    if (libinjXSS) {
        if (!value.empty() && libinjection_xss(value.c_str(), value.size())) {
            applyCheckRule(parser.libxssRule, 1, name, value, zone, false);
        }

        if (!name.empty() && libinjection_xss(name.c_str(), name.size())) {
            applyCheckRule(parser.libxssRule, 1, name, value, zone, true);
        }
    }
}

bool RuntimeScanner::contentDispositionParser(unsigned char *str, unsigned char *line_end,
                                              unsigned char **fvarn_start, unsigned char **fvarn_end,
                                              unsigned char **ffilen_start, unsigned char **ffilen_end) {
    unsigned char *varn_start = NULL, *varn_end = NULL, *filen_start = NULL, *filen_end = NULL;
    /* we have two cases :
    ** ---- file upload
    ** Content-Disposition: form-data; name="somename"; filename="NetworkManager.conf"\r\n
    ** Content-Type: application/octet-stream\r\n\r\n
    ** <DATA>
    ** ---- normal post var
    ** Content-Disposition: form-data; name="lastname"\r\n\r\n
    ** <DATA>
    */

    while (str < line_end) {
        /* rfc allow spaces and tabs inbetween */
        while (str < line_end && *str && (*str == ' ' || *str == '\t'))
            str++;
        if (str < line_end && *str && *str == ';')
            str++;
        while (str < line_end && *str && (*str == ' ' || *str == '\t'))
            str++;

        if (str >= line_end || !*str)
            break;

        if (!strncmp((const char *) str, "name=\"", 6)) {
            /* we already successfully parsed a name, reject that. */
            if (varn_end || varn_start)
                return false;
            varn_end = varn_start = str + 6;
            do {
                varn_end = (unsigned char *) strchr((const char *) varn_end, '"');
                if (!varn_end || (*(varn_end - 1) != '\\'))
                    break;
                varn_end++;
            } while (varn_end && varn_end < line_end);
            if (!varn_end || !*varn_end)
                return false;
            str = varn_end;
            if (str < line_end + 1)
                str++;
            else
                return false;
            *fvarn_start = varn_start;
            *fvarn_end = varn_end;
        } else if (!strncmp((const char *) str, "filename=\"", 10)) {
            /* we already successfully parsed a filename, reject that. */
            if (filen_end || filen_start)
                return false;
            filen_end = filen_start = str + 10;
            do {
                filen_end = (unsigned char *) strchr((const char *) filen_end, '"');
                if (!filen_end) break;
                if (*(filen_end - 1) != '\\')
                    break;
                filen_end++;
            } while (filen_end && filen_end < line_end);
            if (!filen_end)
                return false;
            str = filen_end;
            if (str < line_end + 1)
                str++;
            else
                return false;
            *ffilen_end = filen_end;
            *ffilen_start = filen_start;
        } else if (str == line_end - 1)
            break;
        else {
            /* garbage is present ?*/
            logg(LOG_LVL_NOTICE, errorLogFile,
                 "extra data in content-disposition ? end:%s, str:%s, diff=%ld\n", line_end, str,
                 line_end - str);
            return false;
        }
    }
    return !(filen_end > line_end || varn_end > line_end);
}

bool RuntimeScanner::parseFormDataBoundary(unsigned char **boundary, unsigned long *boundary_len) {
    unsigned char *h = (unsigned char *) &rawContentType[20];
    unsigned char *end = (unsigned char *) &rawContentType[rawContentType.length()];

    /* skip potential whitespace/tabs */
    while (h < end && *h && (*h == ' ' || *h == '\t'))
        h++;
    if (strncmp((const char *) h, "boundary=", 9))
        return false;
    h += 9;
    *boundary_len = end - h;
    *boundary = h;
    /* RFC 1867/1341 says 70 char max,
       I arbitrarily set min to 3 (yes) */
    return !(*boundary_len > 70 || *boundary_len < 3);
}

void RuntimeScanner::multipartParse(u_char *src, unsigned long len) {
    str_t final_var, final_data;
    u_char *boundary, *varn_start, *varn_end;
    u_char *filen_start, *filen_end;
    u_char *end, *line_end;
    unsigned long boundary_len, varn_len, varc_len, idx;
    int nullbytes;

    /*extract boundary*/
    if (!parseFormDataBoundary(&boundary, &boundary_len)) {
        if (boundary && boundary_len > 1)
            logg(LOG_LVL_NOTICE, errorLogFile, "XX-POST boundary : (%s) : %ld\n", (const char *) boundary,
                 boundary_len);
        applyRuleMatch(parser.uncommonPostBoundary, 1, BODY, "multipart/form-data boundary error", empty, false);
        return;
    }

    /* fetch every line starting with boundary */
    idx = 0;
    while (idx < len) {
        /* if we've reached the last boundary '--' + boundary + '--' + '\r\n'$END */
        /* Authorize requests that don't have the leading \r\n */
        if (idx + boundary_len + 6 == len || idx + boundary_len + 4 == len) {
            if (strncmp((const char *) src + idx, "--", 2) ||
                strncmp((const char *) src + idx + 2, (const char *) boundary, boundary_len) ||
                strncmp((const char *) src + idx + boundary_len + 2, "--", 2)) {
                /* bad closing boundary ?*/
                applyRuleMatch(parser.uncommonPostBoundary, 1, BODY, "multipart/form-data bad closing boundary",
                               (const char *) boundary, false);
                return;
            } else
                break;
        }

        /* --boundary\r\n : New var */
        if ((len - idx < 4 + boundary_len) || src[idx] != '-' || src[idx + 1] != '-' ||
            /* and if it's really followed by a boundary */
            strncmp((const char *) src + idx + 2, (const char *) boundary, boundary_len) ||
            /* and if it's not the last boundary of the buffer */
            idx + boundary_len + 2 + 2 >= len ||
            /* and if it's followed by \r\n */
            src[idx + boundary_len + 2] != '\r' || src[idx + boundary_len + 3] != '\n') {
            /* bad boundary */
            applyRuleMatch(parser.uncommonPostBoundary, 1, BODY, "multipart/form-data bad boundary",
                           (const char *) boundary, false);
            return;
        }
        idx += boundary_len + 4;
        /* we have two cases :
        ** ---- file upload
        ** Content-Disposition: form-data; name="somename"; filename="NetworkManager.conf"\r\n
        ** Content-Type: application/octet-stream\r\n\r\n
        ** <DATA>
        ** ---- normal post var
        ** Content-Disposition: form-data; name="lastname"\r\n\r\n
        ** <DATA>
        */
        if (strncasecmp((const char *) src + idx, "content-disposition: form-data;", 31)) {
            applyRuleMatch(parser.uncommonPostFormat, 1, BODY, "POST data : unknown content-disposition",
                           (const char *) src + idx, false);
            return;
        }
        idx += 31;
        line_end = (u_char *) strchr((const char *) src + idx, '\n');
        if (!line_end) {
            applyRuleMatch(parser.uncommonPostFormat, 1, BODY, "POST data : malformed boundary line", empty, false);
            return;
        }
        /* Parse content-disposition, extract name / filename */
        varn_start = varn_end = filen_start = filen_end = NULL;
        if (!contentDispositionParser(src + idx, line_end, &varn_start, &varn_end, &filen_start, &filen_end)) {
            applyRuleMatch(parser.uncommonPostFormat, 1, BODY, empty, empty, false);
            return;
        }
        /* var name is mandatory */
        if (!varn_start || !varn_end || varn_end <= varn_start) {
            applyRuleMatch(parser.uncommonPostFormat, 1, BODY, "POST data : no 'name' in POST var", empty, false);
            return;
        }
        varn_len = varn_end - varn_start;

        /* If there is a filename, it is followed by a "content-type" line, skip it */
        if (filen_start && filen_end) {
            line_end = (u_char *) strchr((const char *) line_end + 1, '\n');
            if (!line_end) {
                applyRuleMatch(parser.uncommonPostFormat, 1, BODY, "POST data : malformed filename (no content-type ?)",
                               empty, false);
                return;
            }
        }
        /*
        ** now idx point to the end of the
        ** content-disposition: form-data; filename="" name=""
        */
        idx += line_end - (src + idx) + 1;
        if (src[idx] != '\r' || src[idx + 1] != '\n') {
            applyRuleMatch(parser.uncommonPostFormat, 1, BODY, "POST data : malformed content-disposition line", empty,
                           false);
            return;
        }
        idx += 2;
        /* seek the end of the data */
        end = NULL;
        while (idx < len) {
            end = (u_char *) strstr((char *) src + idx, "\r\n--");
            /* file data can contain \x0 */
            while (!end) {
                idx += strlen((const char *) src + idx);
                if (idx < len - 2) {
                    idx++;
                    end = (u_char *) strstr((char *) src + idx, "\r\n--");
                } else
                    break;
            }
            if (!end) {
                applyRuleMatch(parser.uncommonPostFormat, 1, BODY, "POST data : malformed content-disposition line",
                               empty, false);
                return;
            }
            if (!strncmp((const char *) end + 4, (const char *) boundary, boundary_len))
                break;
            else {
                idx += (end - (src + idx)) + 1;
                end = NULL;
            }
        }
        if (!end) {
            logg(LOG_LVL_NOTICE, errorLogFile, "POST data : malformed line\n");
            return;
        }
        if (filen_start) {
            final_var.data = varn_start;
            final_var.len = varn_len;
            final_data.data = filen_start;
            final_data.len = filen_end - filen_start;
            nullbytes = naxsi_unescape(&final_var);
            if (nullbytes > 0) {
                applyRuleMatch(parser.uncommonHexEncoding, 1, BODY, empty, empty, true);
            }
            nullbytes = naxsi_unescape(&final_data);
            if (nullbytes > 0) {
                applyRuleMatch(parser.uncommonHexEncoding, 1, BODY, empty, empty, false);
            }

            /* here we got val name + val content !*/
            string finalVar = string((char *) final_var.data, final_var.len);
            string finalData = string((char *) final_data.data, final_data.len);
            transform(finalVar.begin(), finalVar.end(), finalVar.begin(), tolower);
            transform(finalData.begin(), finalData.end(), finalData.begin(), tolower);
//            cerr << finalVar << ":" << finalData << endl;
            basestrRuleset(FILE_EXT, finalVar, finalData, bodyRules);

            idx += end - (src + idx);
        } else if (varn_start) {
            varc_len = end - (src + idx);
            final_var.data = varn_start;
            final_var.len = varn_len;
            final_data.data = src + idx;
            final_data.len = varc_len;
            nullbytes = naxsi_unescape(&final_var);
            if (nullbytes > 0) {
                applyRuleMatch(parser.uncommonHexEncoding, 1, BODY, empty, empty, true);
            }
            nullbytes = naxsi_unescape(&final_data);
            if (nullbytes > 0) {
                applyRuleMatch(parser.uncommonHexEncoding, 1, BODY, empty, empty, false);
            }

            /* here we got val name + val content !*/
            string finalVar = string((char *) final_var.data, final_var.len);
            string finalData = string((char *) final_data.data, final_data.len);
            transform(finalVar.begin(), finalVar.end(), finalVar.begin(), tolower);
            transform(finalData.begin(), finalData.end(), finalData.begin(), tolower);
//            cerr << finalVar << ":" << finalData << endl;
            basestrRuleset(BODY, finalVar, finalData, bodyRules);

            idx += end - (src + idx);
        } else {
            logg(LOG_LVL_NOTICE, errorLogFile, "(multipart) : \n");
        }
        if (!strncmp((const char *) end, "\r\n", 2))
            idx += 2;
    }
}

/*
 * decode url (key=val&key2=val2...)
 * splits the string into key/val pair
 * apply rules to key/val
 */
bool RuntimeScanner::splitUrlEncodedRuleset(char *str, const vector<http_rule_t> &rules, MATCH_ZONE zone) {
    str_t name, val;
    char *eq, *ev, *orig;
    unsigned long len, full_len;
    int nullbytes = 0;
    string key, value;

    orig = str;
    full_len = strlen(orig);
    while (str < (orig + full_len) && *str) {
        if (*str == '&') {
            str++;
            continue;
        }
        if ((block && !learning) || drop)
            return false;
        eq = strchr(str, '=');
        ev = strchr(str, '&');

        if ((!eq && !ev) /*?foobar */ || (eq && ev && eq > ev)) /*?foobar&bla=test*/ {
            logg(LOG_LVL_DEBUG, errorLogFile, "XX-url has no '&' and '=' or has both [%s]\n", str);

            if (!ev)
                ev = str + strlen(str);
            /* len is now [name] */
            len = ev - str;
            value = string(str, ev - str);
            val.data = (unsigned char *) &value[0];
            val.len = value.length();
            key.clear();
            name.data = NULL;
            name.len = 0;
        }
            /* ?&&val | ?var&& | ?val& | ?&val | ?val&var */
        else if (!eq) {
            logg(LOG_LVL_DEBUG, errorLogFile, "XX-url has no '=' but has '&' [%s]\n", str);

            applyRuleMatch(parser.uncommonUrl, 1, zone, empty, empty, false);
            if (ev > str) /* ?var& | ?var&val */ {
                value = string(str, ev - str);
                val.data = (unsigned char *) &value[0];
                val.len = value.length();
                key.clear();
                name.data = NULL;
                name.len = 0;
                len = ev - str;
            } else /* ?& | ?&&val */ {
                val.data = name.data = NULL;
                val.len = name.len = 0;
                len = 1;
            }
        } else /* should be normal like ?var=bar& ..*/ {
            if (!ev) /* ?bar=lol */
                ev = str + strlen(str);
            /* len is now [name]=[content] */
            len = ev - str;
            eq = strnchr(str, '=', len);
            if (!eq) {
                applyRuleMatch(parser.uncommonUrl, 1, zone, "malformed url, possible attack", empty, false);
                return true;
            }
            eq++;
            key = string(str, eq - str - 1);
            name.data = (unsigned char *) &key[0];
            name.len = key.length();
            value = string(eq, ev - eq);
            val.data = (unsigned char *) &value[0];
            val.len = value.length();
        }

        if (name.len) {
            nullbytes = naxsi_unescape(&name);
            key.resize(name.len);
            if (nullbytes > 0) {
                applyRuleMatch(parser.uncommonUrl, 1, zone, (char *) name.data, (char *) val.data, true);
            }
        }
        if (val.len) {
            nullbytes = naxsi_unescape(&val);
            value.resize(val.len);
            if (nullbytes > 0) {
                applyRuleMatch(parser.uncommonUrl, 1, zone, (char *) name.data, (char *) val.data, false);
            }
        }

//        cerr << key << ":" << value << endl;
        transform(key.begin(), key.end(), key.begin(), tolower);
        transform(value.begin(), value.end(), value.begin(), tolower);
        basestrRuleset(zone, key, value, rules);

        str += len;
    }
    return false;
}

void RuntimeScanner::setUri(char *uri_path) {
    uri = string(uri_path);
    transform(uri.begin(), uri.end(), uri.begin(), tolower);
}

void RuntimeScanner::addHeader(char *key, char *val) {
    string k = string(key);
    string v = string(val);
    transform(k.begin(), k.end(), k.begin(), tolower);
    transform(v.begin(), v.end(), v.begin(), tolower);
    // Retrieve Content-Length
    if (k == "content-length") {
        contentLengthProvided = true;
        try {
            contentLength = std::stoul(v);
            if (contentLength > bodyLimit)
                bodyLimitExceeded = true;
        }
        catch (std::exception const &e) {
            logg(LOG_LVL_NOTICE, errorLogFile, "%s cannot convert content-length: '%s' to integer\n",
                 e.what(), v.c_str());
            bodyLimitExceeded = true;
        }
    }
        // Store Content-Type for further processing
    else if (k == "content-type") {
        if (v == "application/x-www-form-urlencoded") {
            contentType = CONTENT_TYPE_URL_ENC;
        } else if (v.substr(0, 20) == "multipart/form-data;") {
            contentType = CONTENT_TYPE_MULTIPART;
            rawContentType = string(val); // important: need to keep the case!
        } else if (v == "application/json") {
            contentType = CONTENT_TYPE_APP_JSON;
        }
    }
        // Retrieve Transfer-encoding
    else if (k == "transfer-encoding") {
        transferEncodingProvided = true;
        if (v == "chunked") {
            transferEncoding = TRANSFER_ENCOING_CHUNKED;
        }
    }
    headers.push_back(make_pair(k, v));
}

void RuntimeScanner::addGETParameter(char *key, char *val) {
    string k = string(key);
    string v = string(val);
    transform(k.begin(), k.end(), k.begin(), tolower);
    transform(v.begin(), v.end(), v.begin(), tolower);
    get.push_back(make_pair(k, v));
}

int RuntimeScanner::processHeaders() {
    // Scan headers
    for (pair<string, string> &headerPair : headers)
        basestrRuleset(HEADERS, headerPair.first, headerPair.second, headerRules);

    // Scan GET parameters
    for (const pair<string, string> &getPair : get)
        basestrRuleset(ARGS, getPair.first, getPair.second, getRules);

    // Scan URL path
    basestrRuleset(URL, empty, uri, genericRules);

    if (method == METHOD_POST || method == METHOD_PUT)
        return PASS;

    return processAction();
}

int RuntimeScanner::processBody() {
    /* Process only if POST / PUT request */
    if (method != METHOD_POST && method != METHOD_PUT)
        return PASS;

    /* Stop if BODY size exceeded the limit */
    if (bodyLimitExceeded) {
        applyRuleMatch(parser.bigRequest, 1, BODY, empty, empty, false);
        return processAction();
    }

    /* Stop if BODY is empty */
    if (body.empty()) {
        applyRuleMatch(parser.emptyPostBody, 1, BODY, empty, empty, false);
        return processAction();
    }

    if (contentType == CONTENT_TYPE_UNSUPPORTED) {
        applyRuleMatch(parser.uncommonContentType, 1, HEADERS, empty, empty, false);
        return processAction();
    }

    /* If Content-Type: application/x-www-form-urlencoded */
    if (contentType == CONTENT_TYPE_URL_ENC) {
        if (splitUrlEncodedRuleset(&body[0], bodyRules, BODY)) {
            applyRuleMatch(parser.uncommonUrl, 1, BODY, empty, empty, false);
        }
    }
        /* If Content-Type: multipart/form-data */
    else if (contentType == CONTENT_TYPE_MULTIPART) {
        multipartParse((u_char *) &body[0], body.length());
    }
        /* If Content-Type: application/json */
    else if (contentType == CONTENT_TYPE_APP_JSON) {
        JsonValidator jsonValidator = JsonValidator(*this);
        jsonValidator.jsonParse((u_char *) &body[0], body.length());
    }
        /* Raw Body */
    else {
        str_t raw_body;
        raw_body.data = (u_char *) &body[0];
        raw_body.len = body.length();

        naxsi_unescape(&raw_body);
        body.resize(raw_body.len);

        basestrRuleset(RAW_BODY, empty, body, rawBodyRules);
    }

    return processAction();
}

int RuntimeScanner::processAction() {
    writeLearningLog();
    writeJSONLearningLog();

    if ((block && !learning) || drop)
        return STOP;

    return PASS;
}

void RuntimeScanner::streamToFile(const stringstream &ss, void *file) {
    if (!file) return;
    const string tmp = ss.str();
    size_t loglen = tmp.size();
    writeLogFn(file, tmp.c_str(), &loglen);
}

void RuntimeScanner::logg(int priority, void *file, const char *fmt, ...) {
    if (priority > logLevel)
        return;
    va_list args;
    char logbuf[256] = {0};
    va_start(args, fmt);
    vsnprintf(logbuf, 256, fmt, args);
    va_end(args);
    size_t loglen = strlen(logbuf);
    writeLogFn(file, logbuf, &loglen);
}

/*
 * YYYY/MM/DD HH:MM:SS [LEVEL] PID#TID: *CID MESSAGE
 */
void RuntimeScanner::writeLearningLog() {
    if (rulesMatchedCount == 0)
        return;

    stringstream learninglog;
    learninglog << naxsiTimeFmt() << " ";
    learninglog << "[error] ";
    learninglog << pid << "#";
    learninglog << threadId << ": ";
    learninglog << "*" << connectionId << " ";

    learninglog << "NAXSI_FMT: ";

    learninglog << "ip=" << clientIp << "&";
    learninglog << "server=" << requestedHost << "&";
    learninglog << "uri=" << uri << "&";

    learninglog << "learning=" << learning << "&";
    learninglog << "vers=" << softwareVersion << "&";

    learninglog << "block=" << (block || drop) << "&";
    int i = 0;
    for (const auto &match : matchScores) {
        learninglog << "cscore" << i << "=" << match.first << "&";
        learninglog << "score" << i << "=" << match.second << "&";
        i++;
    }

    learninglog << matchVars.str();

    learninglog << ", ";

    learninglog << "client: " << clientIp << ", ";
    learninglog << "server: " << serverHostname << ", ";
    learninglog << "request: \"" << methods[method] << " " << fullUri << " " << protocol << "\", ";
    learninglog << "host: \"" << requestedHost << "\"";

    learninglog << endl;
    streamToFile(learninglog, learningLogFile);
}

void RuntimeScanner::writeExtensiveLog(const http_rule_t &rule, MATCH_ZONE zone, const string &name,
                                       const string &value, bool targetName) {
    if (!extensiveLearning)
        return;
    stringstream extensivelog;
    extensivelog << naxsiTimeFmt() << " ";
    extensivelog << "[error] ";
    extensivelog << pid << "#";
    extensivelog << threadId << ": ";
    extensivelog << "*" << connectionId << " ";

    extensivelog << "NAXSI_EXLOG: ";

    extensivelog << "ip=" << clientIp << "&";
    extensivelog << "server=" << serverHostname << "&";
    extensivelog << "uri=" << uri << "&";

    extensivelog << "id=" << rule.id << "&";
    extensivelog << "zone=" << match_zones[zone];
    if (targetName)
        extensivelog << "|NAME";
    extensivelog << "&";
    extensivelog << "var_name=" << name << "&";
    extensivelog << "content=" << value << ",";

    extensivelog << "client: " << clientIp << ", ";
    extensivelog << "server: " << serverHostname << ", ";
    extensivelog << "request: \"" << methods[method] << " " << fullUri << " " << protocol << "\", ";
    extensivelog << "host: \"" << requestedHost << "\"";

    extensivelog << endl;
    streamToFile(extensivelog, learningLogFile);
}

void RuntimeScanner::writeJSONLearningLog() {
    if (rulesMatchedCount == 0)
        return;

    stringstream jsonlog;
    std::time_t result = std::time(nullptr);
    std::asctime(std::localtime(&result));
    jsonlog << "{\"timestamp\":";
    jsonlog << result << ",";

    jsonlog << "\"ip\":\"" << clientIp << "\",";
    jsonlog << "\"hostname\":\"" << requestedHost << "\",";
    jsonlog << "\"uri\":\"" << uri << "\",";

    jsonlog << "\"block\":" << (block || drop) << ",";
    jsonlog << "\"scores\":{";
    int i = 0;
    for (const auto &match : matchScores) {
        string scoreName = match.first.substr(1, match.first.length() - 1);
        transform(scoreName.begin(), scoreName.end(), scoreName.begin(), tolower);
        jsonlog << "\"" << scoreName << "\":" << match.second << ",";
        i++;
    }
    if (i > 0) jsonlog.seekp(-1, std::ios_base::end);
    jsonlog << "},";

    jsonlog << "\"vars\":[" << jsonMatchVars.str() << "],";

    jsonlog << "\"client\":\"" << clientIp << "\",";
    jsonlog << "\"server\":\"" << serverHostname << "\",";
    jsonlog << "\"method\":\"" << methods[method] << "\",";
    jsonlog << "\"protocol\":\"" << protocol << "\",";
    jsonlog << "\"unparsed_uri\":\"" << fullUri << "\"";

    jsonlog << "}" << endl;
    streamToFile(jsonlog, learningJSONLogFile);
}
