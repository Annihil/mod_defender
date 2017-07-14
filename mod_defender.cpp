/*                       _        _       __                _
 *   _ __ ___   ___   __| |    __| | ___ / _| ___ _ __   __| | ___ _ __
 *  | '_ ` _ \ / _ \ / _` |   / _` |/ _ \ |_ / _ \ '_ \ / _` |/ _ \ '__|
 *  | | | | | | (_) | (_| |  | (_| |  __/  _|  __/ | | | (_| |  __/ |
 *  |_| |_| |_|\___/ \__,_|___\__,_|\___|_|  \___|_| |_|\__,_|\___|_|
 *                       |_____|
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */

#include <http_request.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <apr_strings.h>
#include <util_script.h>
#include <unistd.h>
#include "deps/libdefiance/RuntimeScanner.hpp"

// Extra Apache 2.4+ C++ module declaration
#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(defender);
#endif

/*
 * Per-directory configuration structure
 */
typedef struct {
    RuleParser *parser;
    std::vector<std::pair<std::string, std::string>> tmpCheckRules;
    std::vector<std::string> tmpBasicRules;
    char *loc_path;
    apr_file_t *matchlog_file;
    apr_file_t *jsonmatchlog_file;
    unsigned long requestBodyLimit;
    bool libinjection_sql;
    bool libinjection_xss;
    bool defender;
    bool learning;
    bool extensive;
    bool useenv;
} dir_config_t;

std::vector<dir_config_t *> dir_cfgs;

extern module AP_MODULE_DECLARE_DATA defender_module;

/* Custom definition to hold any configuration data we may need. */
typedef struct {
    RuntimeScanner *vpRuntimeScanner;
} defender_config_t;

/* Custom function to ensure our RuntimeScanner get's deleted at the
   end of the request cycle. */
static apr_status_t defender_delete_runtimescanner_object(void *inPtr) {
    if (inPtr)
        delete (RuntimeScanner *) inPtr;
    return OK;
}

static apr_status_t defender_delete_ruleparser_object(void *inPtr) {
    if (inPtr) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "Unloading Defender for a loc");
        delete (RuleParser *) inPtr;
    }
    return OK;
}

/*
 * This routine is called after the server finishes the configuration
 * process.  At this point the module may review and adjust its configuration
 * settings in relation to one another and report any problems.  On restart,
 * this routine will be called only once, in the running server process.
 */
static int post_config(apr_pool_t *pconf, apr_pool_t *, apr_pool_t *, server_rec *s) {
    /* Figure out if we are here for the first time */
    void *init_flag = NULL;
    apr_pool_userdata_get(&init_flag, "defender-init-flag", s->process->pool);
    if (init_flag == NULL) { // first load
        apr_pool_userdata_set((const void *) 1, "defender-init-flag", apr_pool_cleanup_null, s->process->pool);
        tmpMainRules.clear();
    } else { // second (last) load
        std::string mainruleErr;
        unsigned int mainRuleCount = RuleParser::parseMainRules(tmpMainRules, mainruleErr);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "Defender active on server %s: %d MainRules loaded",
                     s->server_hostname, mainRuleCount);
        if (!mainruleErr.empty())
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "MainRules error %s", mainruleErr.c_str());

        for (int i = 0; i < dir_cfgs.size(); i++) {
            dir_config_t *dcfg = dir_cfgs[i];
            if (dcfg->defender) {
                dcfg->parser = new RuleParser();
                apr_pool_cleanup_register(pconf, (void *) dcfg->parser, defender_delete_ruleparser_object,
                                          apr_pool_cleanup_null);
                std::string checkruleErr;
                dcfg->parser->parseCheckRule(dcfg->tmpCheckRules, checkruleErr);
                std::string basicruleErr;
                unsigned int basicRuleCount = dcfg->parser->parseBasicRules(dcfg->tmpBasicRules, basicruleErr);
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                             "Defender active%s on loc %s: %lu CheckRules loaded, %d BasicRules loaded",
                             (dcfg->learning ? " (learning)" : ""), dcfg->loc_path, dcfg->parser->checkRules.size(),
                             basicRuleCount);
                if (!checkruleErr.empty())
                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "CheckRule parsing error %s", checkruleErr.c_str());
                if (!basicruleErr.empty())
                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "BasicRule parsing error %s", basicruleErr.c_str());
                dcfg->parser->generateHashTables();
            } else {
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "Defender scanner disabled for loc %s",
                             dcfg->loc_path);
            }
        }
    }
    dir_cfgs.clear();
    return OK;
}

static int pass_in_env(request_rec *r, RuntimeScanner *scanner) {
    if ((scanner->block && !scanner->learning) || scanner->drop)
        apr_table_set(r->subprocess_env, "defender_action", "block");
    for (const auto &match : scanner->matchScores) {
        apr_table_set(r->subprocess_env, apr_psprintf(r->pool, "defender_%s", match.first.c_str()),
                      apr_itoa(r->pool, match.second));
    }
    return DECLINED;
}

static int write_log(void *thefile, const void *buf, size_t *nbytes) {
    return apr_file_write((apr_file_t *) thefile, buf, nbytes);
}

/*
 * this routine gives our module another chance to examine the request
 * headers and to take special action. This is the first phase whose
 * hooks' configuration directives can appear inside the <Directory>
 * and similar sections, because at this stage the URI has been mapped
 * to the filename. For example this phase can be used to block evil
 * clients, while little resources were wasted on these.
 *
 * This is a RUN_ALL hook.
 */
static int header_parser(request_rec *r) {
    // Get the module configuration
    dir_config_t *dcfg = (dir_config_t *) ap_get_module_config(r->per_dir_config, &defender_module);

    // Stop if Defender not enabled
    if (!dcfg->defender)
        return DECLINED;

    RuntimeScanner *scanner = new RuntimeScanner(*dcfg->parser);

    // Register a C function to delete scanner at the end of the request cycle
    apr_pool_cleanup_register(r->pool, (void *) scanner, defender_delete_runtimescanner_object,
                              apr_pool_cleanup_null);

    // Reserve a temporary memory block from the request pool to store data between hooks
    defender_config_t *pDefenderConfig = (defender_config_t *) apr_palloc(r->pool, sizeof(defender_config_t));

    // Remember our application pointer for future calls
    pDefenderConfig->vpRuntimeScanner = scanner;

    // Register our config data structure for our module for retrieval later as required
    ap_set_module_config(r->request_config, &defender_module, (void *) pDefenderConfig);

    // Set method
    if (r->method_number == M_GET)
        scanner->method = METHOD_GET;
    else if (r->method_number == M_POST)
        scanner->method = METHOD_POST;
    else if (r->method_number == M_PUT)
        scanner->method = METHOD_PUT;

    // Set logger info
    scanner->pid = getpid();
    apr_os_thread_t tid = apr_os_thread_current();
    unsigned int pid_buffer_len = 16;
    char pid_buffer[pid_buffer_len];
    apr_snprintf(pid_buffer, pid_buffer_len, "%pT", &tid);
    scanner->threadId = std::string(pid_buffer);
    scanner->connectionId = r->connection->id;
    scanner->clientIp = r->useragent_ip;
    scanner->requestedHost = r->hostname;
    scanner->serverHostname = r->server->server_hostname;
    scanner->fullUri = r->unparsed_uri;
    scanner->protocol = r->protocol;
    ap_version_t vers;
    ap_get_server_revision(&vers);
    scanner->softwareVersion = std::to_string(vers.major) + "." + std::to_string(vers.minor) + "." +
                               std::to_string(vers.patch);
    scanner->logLevel = static_cast<LOG_LVL>(r->log->level);
    if (scanner->logLevel >= APLOG_DEBUG)
        scanner->logLevel = LOG_LVL_DEBUG;
    scanner->writeLogFn = write_log;
    scanner->errorLogFile = r->server->error_log;
    scanner->learningLogFile = dcfg->matchlog_file;
    scanner->learningJSONLogFile = dcfg->jsonmatchlog_file;
    scanner->learning = dcfg->learning;
    scanner->extensiveLearning = dcfg->extensive;

    // Set runtime modifiers
    scanner->libinjSQL = dcfg->libinjection_sql;
    scanner->libinjXSS = dcfg->libinjection_xss;
    scanner->bodyLimit = dcfg->requestBodyLimit;

    // Set the uri path
    scanner->setUri(r->parsed_uri.path);

    // Pass every HTTP header received
    const apr_array_header_t *headerFields = apr_table_elts(r->headers_in);
    apr_table_entry_t *headerEntry = (apr_table_entry_t *) headerFields->elts;
    for (int i = 0; i < headerFields->nelts; i++)
        scanner->addHeader(headerEntry[i].key, headerEntry[i].val);

    // Pass GET parameters
    apr_table_t *getTable = NULL;
    ap_args_to_table(r, &getTable);
    const apr_array_header_t *getParams = apr_table_elts(getTable);
    apr_table_entry_t *getParam = (apr_table_entry_t *) getParams->elts;
    for (int i = 0; i < getParams->nelts; i++)
        scanner->addGETParameter(getParam[i].key, getParam[i].val);

    // Run scanner
    int ret = scanner->processHeaders();

    if (dcfg->useenv)
        ret = pass_in_env(r, scanner);

    return ret;
}

static char *get_apr_error(apr_pool_t *p, apr_status_t rc) {
    char *text = (char *) apr_pcalloc(p, 201);
    if (text == NULL) return NULL;
    apr_strerror(rc, text, 200);
    return text;
}

/*
 * This routine is called to perform any module-specific fixing of header
 * fields, et cetera.  It is invoked just before any content-handler.
 *
 * This is a RUN_ALL HOOK.
 */
static int fixups(request_rec *r) {
    int ret;
    dir_config_t *dcfg = (dir_config_t *) ap_get_module_config(r->per_dir_config, &defender_module);
    // Stop if Defender not enabled
    if (!dcfg->defender)
        return DECLINED;

    // Stop if this is not the main request
    if (r->main != NULL || r->prev != NULL)
        return DECLINED;

    // Process only if POST / PUT request
    if (r->method_number != M_POST && r->method_number != M_PUT)
        return DECLINED;

    defender_config_t *defc = (defender_config_t *) ap_get_module_config(r->request_config, &defender_module);
    RuntimeScanner *scanner = defc->vpRuntimeScanner;

    if (scanner->contentLengthProvided && scanner->contentLength == 0)
        return scanner->processBody();

    if (scanner->contentType == CONTENT_TYPE_UNSUPPORTED)
        return scanner->processBody();

    if (scanner->bodyLimitExceeded)
        return scanner->processBody();

    if (!scanner->contentLengthProvided)
        return HTTP_NOT_IMPLEMENTED;

    if (scanner->transferEncodingProvided /*&& scanner->transferEncoding == TRANSFER_ENCODING_UNSUPPORTED*/)
        return HTTP_NOT_IMPLEMENTED;

    // Retrieve the body
    // Pre-allocate necessary bytes
    scanner->body.reserve(scanner->contentLength);

    // Wait for the body to be fully received 
    apr_bucket_brigade *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    unsigned int prev_nr_buckets = 0;
    if (bb == NULL)
        goto read_error_out;
    do {
        int rc = ap_get_brigade(r->input_filters, bb, AP_MODE_SPECULATIVE, APR_BLOCK_READ, LONG_MAX);
        if (rc != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Error reading body: %s", get_apr_error(r->pool, rc));
            goto read_error_out;
        }

        unsigned int nr_buckets = 0;
        // Iterate over buckets
        for (apr_bucket *bucket = APR_BRIGADE_FIRST(bb);
             bucket != APR_BRIGADE_SENTINEL(bb); bucket = APR_BUCKET_NEXT(bucket)) {
            // Stop if we reach the EOS bucket
            if (APR_BUCKET_IS_EOS(bucket))
                break;

            // Ignore non data buckets
            if (APR_BUCKET_IS_METADATA(bucket) || APR_BUCKET_IS_FLUSH(bucket))
                continue;

            nr_buckets++;
            // Skip already copied buckets
            if (nr_buckets <= prev_nr_buckets)
                continue;

            const char *buf;
            apr_size_t nbytes;
            int rv = apr_bucket_read(bucket, &buf, &nbytes, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Failed reading input / bucket: %s",
                              get_apr_error(r->pool, rv));
                goto read_error_out;
            }

//            cerr << "bucket #" << nr_buckets - 1 << " received, nbytes: " << nbytes << ", total len: "
//                 << scanner->body.length() + nbytes << endl;

            // More bytes in the BODY than specified in the content-length
            if (scanner->body.length() + nbytes > scanner->contentLength) {
                ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Too much POST data: received body of %lu bytes but "
                        "got content-length: %lu", scanner->body.length() + nbytes, scanner->contentLength);
                goto read_error_out;
            }

            // More bytes in the BODY than specified by the allowed body limit
            if (scanner->body.length() + nbytes > dcfg->requestBodyLimit) {
                scanner->bodyLimitExceeded = true;
                ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Body limit exceeded (%lu)", dcfg->requestBodyLimit);
                break;
            }

            scanner->body.append(buf, nbytes);
        }
        prev_nr_buckets = nr_buckets;

        if (scanner->body.length() == scanner->contentLength)
            break;

        apr_brigade_cleanup(bb);
        apr_sleep(1000);
    } while (true);

//    cerr << "[pid " << getpid() << "] read " << scanner->body.length() << " bytes, ";
//    cerr << "content-length: " << scanner->contentLength << endl;
//    cerr << "body: " << scanner->body << endl;

    // Run scanner
    ret = scanner->processBody();

    if (dcfg->useenv)
        ret = pass_in_env(r, scanner);

//    cerr << "[pid " << getpid() << "] body (" << scanner->body.length() << ") scanned" << endl;

    return ret;

    read_error_out:
    if (dcfg->useenv) return DECLINED;
    return HTTP_INTERNAL_SERVER_ERROR;
}

/* Apache callback to register our hooks.
 */
static void defender_register_hooks(apr_pool_t *) {
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    static const char *const aszSucc[] = {"mod_security2.c", NULL};
    ap_hook_header_parser(header_parser, NULL, aszSucc, APR_HOOK_REALLY_FIRST - 20);
    ap_hook_fixups(fixups, NULL, aszSucc, APR_HOOK_REALLY_FIRST - 20);
}

/**
 * This function is called when the "MatchLog" configuration directive is parsed.
 */
static const char *set_matchlog_path(cmd_parms *cmd, void *cfg, const char *arg) {
    dir_config_t *dcfg = (dir_config_t *) cfg;

    char *matchlog_path = apr_pstrdup(cmd->pool, arg);

    if (matchlog_path[0] == '|') {
        const char *pipe_name = matchlog_path + 1;
        piped_log *pipe_log;

        pipe_log = ap_open_piped_log(cmd->pool, pipe_name);
        if (pipe_log == NULL)
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the match log pipe: %s", pipe_name);
        dcfg->matchlog_file = ap_piped_log_write_fd(pipe_log);
    } else {
        const char *file_name = ap_server_root_relative(cmd->pool, matchlog_path);
        apr_status_t rc;

        rc = apr_file_open(&dcfg->matchlog_file, file_name,
                           APR_WRITE | APR_APPEND | APR_CREATE | APR_BINARY,
                           APR_UREAD | APR_UWRITE | APR_GREAD, cmd->pool);

        if (rc != APR_SUCCESS)
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the match log file: %s", file_name);
    }

    return NULL; // success
}

/**
 * This function is called when the "JSONMatchLog" configuration directive is parsed.
 */
static const char *set_jsonerrorlog_path(cmd_parms *cmd, void *cfg, const char *arg) {
    dir_config_t *dcfg = (dir_config_t *) cfg;

    char *jsonmatchlog_path = apr_pstrdup(cmd->pool, arg);

    if (jsonmatchlog_path[0] == '|') {
        const char *pipe_name = jsonmatchlog_path + 1;
        piped_log *pipe_log;

        pipe_log = ap_open_piped_log(cmd->pool, pipe_name);
        if (pipe_log == NULL)
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the json match log pipe: %s", pipe_name);
        dcfg->jsonmatchlog_file = ap_piped_log_write_fd(pipe_log);
    } else {
        const char *file_name = ap_server_root_relative(cmd->pool, jsonmatchlog_path);
        apr_status_t rc;

        rc = apr_file_open(&dcfg->jsonmatchlog_file, file_name,
                           APR_WRITE | APR_APPEND | APR_CREATE | APR_BINARY,
                           APR_UREAD | APR_UWRITE | APR_GREAD, cmd->pool);

        if (rc != APR_SUCCESS)
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the json match log file: %s", file_name);
    }

    return NULL; // success
}

static const char *set_request_body_limit(cmd_parms *cmd, void *cfg, const char *arg) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    unsigned long limit = strtoul(arg, NULL, 10);
    if (limit <= 0)
        return apr_psprintf(cmd->pool, "mod_defender: Invalid value for RequestBodyLimit: %s", arg);
    dcfg->requestBodyLimit = limit;
    return NULL;
}

static const char *set_libinjection_sql_flag(cmd_parms *, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->libinjection_sql = (bool) flag;
    return NULL;
}

static const char *set_libinjection_xss_flag(cmd_parms *, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->libinjection_xss = (bool) flag;
    return NULL;
}

static const char *set_defender_flag(cmd_parms *, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->defender = (bool) flag;
    return NULL;
}

static const char *set_learning_flag(cmd_parms *, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->learning = (bool) flag;
    return NULL;
}

static const char *set_extensive_flag(cmd_parms *, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->extensive = (bool) flag;
    return NULL;
}

static const char *set_useenv_flag(cmd_parms *, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->useenv = (bool) flag;
    return NULL;
}

static const char *set_mainrules(cmd_parms *, void *, const char *line) {
    tmpMainRules.push_back(std::string(line));
    return NULL;
}

static const char *set_checkrules(cmd_parms *, void *cfg, const char *arg1, const char *arg2) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->tmpCheckRules.push_back(std::make_pair(std::string(arg1), std::string(arg2)));
    return NULL;
}

static const char *set_basicrules(cmd_parms *, void *cfg, const char *line) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->tmpBasicRules.push_back(std::string(line));
    return NULL;
}

/**
 * A declaration of the configuration directives that are supported by this module.
 */
static const command_rec directives[] = {
        {"Defender",         (cmd_func) set_defender_flag,         NULL, ACCESS_CONF, FLAG,     "Defender toggle"},
        {"MainRule",         (cmd_func) set_mainrules,             NULL, RSRC_CONF,   RAW_ARGS, "Match directive"},
        {"CheckRule",        (cmd_func) set_checkrules,            NULL, ACCESS_CONF, TAKE2,    "Score directive"},
        {"BasicRule",        (cmd_func) set_basicrules,            NULL, ACCESS_CONF, RAW_ARGS, "Whitelist directive"},
        {"MatchLog",         (cmd_func) set_matchlog_path,         NULL, ACCESS_CONF, TAKE1,    "Path to the match log"},
        {"JSONMatchLog",     (cmd_func) set_jsonerrorlog_path,     NULL, ACCESS_CONF, TAKE1,    "Path to the JSON match log"},
        {"RequestBodyLimit", (cmd_func) set_request_body_limit,    NULL, ACCESS_CONF, TAKE1,    "Set Request Body Limit"},
        {"LearningMode",     (cmd_func) set_learning_flag,         NULL, ACCESS_CONF, FLAG,     "Learning mode toggle"},
        {"ExtensiveLog",     (cmd_func) set_extensive_flag,        NULL, ACCESS_CONF, FLAG,     "Extensive log toggle"},
        {"LibinjectionSQL",  (cmd_func) set_libinjection_sql_flag, NULL, ACCESS_CONF, FLAG,     "Libinjection SQL toggle"},
        {"LibinjectionXSS",  (cmd_func) set_libinjection_xss_flag, NULL, ACCESS_CONF, FLAG,     "Libinjection XSS toggle"},
        {"UseEnv",           (cmd_func) set_useenv_flag,           NULL, ACCESS_CONF, FLAG,     "UseEnv toggle"},
        {NULL}
};

/**
 * Creates the per-server configuration records.
 */
static void *create_dir_config(apr_pool_t *p, char *path) {
    // allocate space for the configuration structure from the provided pool p.
    dir_config_t *dcfg = (dir_config_t *) apr_pcalloc(p, sizeof(dir_config_t));

    dir_cfgs.push_back(dcfg);
    dcfg->loc_path = apr_pstrdup(p, path);
    return dcfg;
}

/* Our standard module definition.
 */
module AP_MODULE_DECLARE_DATA defender_module = {
        STANDARD20_MODULE_STUFF,
        create_dir_config,
        NULL,
        NULL, // create per-server configuration structures.,
        NULL, // merge per-server configurations
        directives, // configuration directive handlers,
        defender_register_hooks // request handlers
};