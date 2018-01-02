#ifndef __DIR_CRAWLER_H__
#define __DIR_CRAWLER_H__

/* --- INCLUDES ------------------------------------------------------------- */
#include <Shlobj.h>
#define UTILS_REQUIRE_GETOPT_COMPLEX
#define STATIC_GETOPT
#define LIB_ERROR_VAL NOT_USED
#include <UtilsLib.h>
#include <LogLib.h>
#include <LdapLib.h>
#include <LdapHelpers.h>
#include <CsvLib.h>

/* --- DEFINES -------------------------------------------------------------- */

//
// Misc
//
#define DIR_CRAWLER_TOOL_NAME           _T("DirectoryCrawler")
#define DEFAULT_OPT_LOG_LEVEL           _T("WARN")
#define DIR_CRAWLER_HEAP_NAME           DIR_CRAWLER_TOOL_NAME
#define DIR_CRAWLER_LDAP_VAL_SEPARATOR  _T(';')
#define DIR_CRAWLER_SEPARATOR_ESCAPE    _T('\\')

//
// Log for requests
//
#define REQ_LOG(req, lvl, frmt, ...)    LOG(lvl, SUB_LOG(_T("[%s] ") ## frmt), (req)->infos.ptName, __VA_ARGS__)
#define REQ_FATAL(req, frmt, ...)       MULTI_LINE_MACRO_BEGIN                      \
                                            REQ_LOG(req, Err, frmt, __VA_ARGS__);   \
                                            GenerateException();                    \
                                        MULTI_LINE_MACRO_END

//
// Outfiles
//
#define DIR_CRAWLER_LOG_DIR             _T("Logs")
#define DIR_CRAWLER_OUTPUT_DIR          _T("Ldap")
#define DIR_CRAWLER_OUTFILES_KEYWORD    _T("LDAP")
#define DIR_CRAWLER_OUTFILES_ROOTDSE    _T("RootDSE")
#define DIR_CRAWLER_OUTFILES_EXT        _T("csv")
#define DIR_CRAWLER_LOGFILE_EXT         _T("log")
#define DIR_CRAWLER_LOGFILE_PREFIX      _T("XX")

/* --- TYPES ---------------------------------------------------------------- */
typedef struct _LDAP_OPTIONS {
    PTCHAR ptLogin;
    PTCHAR ptPassword;
    PTCHAR ptExplicitDomain;
    PTCHAR ptLdapServer;
    DWORD dwLdapPort;
    PTCHAR ptDnsName;
} LDAP_OPTIONS, *PLDAP_OPTIONS;

typedef struct _DIR_CRAWLER_OPTIONS {
    LDAP_OPTIONS ldap;

    struct {
        PTCHAR ptJsonFile;
        PTCHAR ptOutputDir;
        PTCHAR ptRequestSublist;
        struct {
            PTCHAR *pptList;
            DWORD dwCount;
        } requests;
    } dump;

    struct {
        PTCHAR ptLogFile;
        PTCHAR ptLogLevelFile;
        PTCHAR ptLogLevelConsole;
    } log;

    struct {
        BOOL bShowHelp;
        DWORD dwMaxThreads;
        PTCHAR ptOutfilesPrefix;
    } misc;

} DIR_CRAWLER_OPTIONS, *PDIR_CRAWLER_OPTIONS;

typedef enum _DIR_CRAWLER_TYPE {
    DirCrawlerTypeStr,
    DirCrawlerTypeInt,
    DirCrawlerTypeBin,
} DIR_CRAWLER_LDAP_ATTR_TYPE, DIR_CRAWLER_LDAP_CTRLVAL_TYPE;

typedef enum _DIR_CRAWLER_LDAP_CTRL_TYPE {
    DirCrawlerLdapCtrlServer,
    DirCrawlerLdapCtrlClient,
} DIR_CRAWLER_LDAP_CTRL_TYPE;

typedef enum _DIR_CRAWLER_LDAP_BASE_TYPE {
    DirCrawlerLdapBaseNcShortcut,
    DirCrawlerLdapBaseDN,
    DirCrawlerLdapBaseWildcardAll
} DIR_CRAWLER_LDAP_BASE_TYPE;

typedef enum _DIR_CRAWLER_LDAP_NC_SHORTCUT {
    DirCrawlerLdapNcDomain,
    DirCrawlerLdapNcConfiguration,
    DirCrawlerLdapNcSchema,
    DirCrawlerLdapNcDomainDnsZones,
    DirCrawlerLdapNcForestDnsZones,
} DIR_CRAWLER_LDAP_NC_SHORTCUT;

typedef struct _DIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION {
    PTCHAR ptName;
    DIR_CRAWLER_LDAP_ATTR_TYPE eType;
} DIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION, *PDIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION;

typedef struct _DIR_CRAWLER_LDAP_CONTROL_DESCRIPTION {
    PTCHAR ptName;
    PTCHAR ptOid;
    BOOL bHasValue;
    DIR_CRAWLER_LDAP_CTRL_TYPE eCtrlType;
    DIR_CRAWLER_LDAP_CTRLVAL_TYPE eValueType;
    union {
        struct {
            DWORD dwLen;
            PVOID pvVal;
        } bin;
        PTCHAR ptVal;
        INT iVal;
    } value;
} DIR_CRAWLER_LDAP_CONTROL_DESCRIPTION, *PDIR_CRAWLER_LDAP_CONTROL_DESCRIPTION;

typedef struct _DIR_CRAWLER_REQ_DESCR {
    struct {
        PTCHAR ptName;
        PTCHAR ptDescription;
    } infos;

    struct {
        struct {
            DIR_CRAWLER_LDAP_BASE_TYPE eType;
            union {
                DIR_CRAWLER_LDAP_NC_SHORTCUT eBaseNcShortcut;
                PTCHAR ptBaseDN;
            } value;
        } base;

        LDAP_REQ_SCOPE eScope;
        PTCHAR ptFilter;

        struct {
            DWORD dwAttrCount;
            PDIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION pAttrArray;
        } attributes;

        struct {
            DWORD dwCtrlCount;
            PDIR_CRAWLER_LDAP_CONTROL_DESCRIPTION pCtrlArray;
        } controls;

    } ldap;
} DIR_CRAWLER_REQ_DESCR, *PDIR_CRAWLER_REQ_DESCR;

typedef struct _DIR_CRAWLER_REQ_DESCR_ARRAY {
    DIR_CRAWLER_REQ_DESCR *pRequestsDescriptions;
    DWORD dwRequestCount;
} DIR_CRAWLER_REQ_DESCR_ARRAY, *PDIR_CRAWLER_REQ_DESCR_ARRAY;

typedef struct _DIR_CRAWLER_REQ_LIST_ENTRY {
    SLIST_ENTRY sListEntry;
    PDIR_CRAWLER_REQ_DESCR pReqDescr;
} DIR_CRAWLER_REQ_LIST_ENTRY, *PDIR_CRAWLER_REQ_LIST_ENTRY;

/* --- VARIABLES ------------------------------------------------------------ */
extern PUTILS_HEAP g_pDirCrawlerHeap;

/* --- PROTOTYPES ----------------------------------------------------------- */

#endif // __DIR_CRAWLER_H__
