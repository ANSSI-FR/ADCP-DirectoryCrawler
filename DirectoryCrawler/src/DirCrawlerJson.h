#ifndef __DIR_CRAWLER_JSON_H__
#define __DIR_CRAWLER_JSON_H__

/* --- INCLUDES ------------------------------------------------------------- */
#include "DirectoryCrawler.h"
#include "JsonLib.h"

/* --- DEFINES -------------------------------------------------------------- */
//
// JSON tokens
//
#define JSON_TOKEN_DESCR                _T("descr")
#define JSON_TOKEN_LDAP                 _T("ldap")
#define JSON_TOKEN_BASE                 _T("base")
#define JSON_TOKEN_SCOPE                _T("scope")
#define JSON_TOKEN_FILTER               _T("filter")
#define JSON_TOKEN_ATTRS                _T("attrs")
#define JSON_TOKEN_CONTROLS             _T("controls")
#define JSON_TOKEN_TYPE                 _T("type")
#define JSON_TOKEN_NAME                 _T("name")
#define JSON_TOKEN_VALUE                _T("value")
#define JSON_TOKEN_OID                  _T("oid")
#define JSON_TOKEN_CONTROL_TYPE         _T("ctrltype")
#define JSON_TOKEN_VALUE_TYPE           _T("valuetype")

#define JSON_SCOPE_BASE                 _T("base")
#define JSON_SCOPE_ONELEVEL             _T("onelevel")
#define JSON_SCOPE_SUBTREE              _T("subtree")

#define JSON_BASE_WELLKNOW_NC_DOMAIN    _T("domain")
#define JSON_BASE_WELLKNOW_NC_CONFIG    _T("configuration")
#define JSON_BASE_WELLKNOW_NC_SCHEMA    _T("schema")
#define JSON_BASE_WELLKNOW_NC_DOMDNS    _T("domainDns")
#define JSON_BASE_WELLKNOW_NC_FORDNS    _T("forestDns")
#define JSON_BASE_WILDCARD_NC           _T("*")

#define JSON_TYPE_NONE                  _T("none")
#define JSON_TYPE_STR                   _T("str")
#define JSON_TYPE_INT                   _T("int")
#define JSON_TYPE_BIN                   _T("bin")

#define JSON_CONTROL_TYPE_CLIENT        _T("client")
#define JSON_CONTROL_TYPE_SERVER        _T("server")

/* --- TYPES ---------------------------------------------------------------- */
/* --- VARIABLES ------------------------------------------------------------ */
/* --- PROTOTYPES ----------------------------------------------------------- */
void DirCrawlerJsonParseRequestFile(
    _In_ const PTCHAR ptJsonFile,
    _In_ const PDIR_CRAWLER_REQ_DESCR_ARRAY pReqDescr
    );

void DirCrawlerJsonReleaseRequests(
    _In_ const PDIR_CRAWLER_REQ_DESCR_ARRAY pReqDescr
    );

#endif // __DIR_CRAWLER_JSON_H__
