/* --- INCLUDES ------------------------------------------------------------- */
#include "DirectoryCrawler.h"
#include "DirCrawlerJson.h"
#include "DirCrawlerFormatters.h"
#include <Winber.h>

/* --- PRIVATE VARIABLES ---------------------------------------------------- */
static PSLIST_HEADER gs_pReqListHead = NULL;
static DIR_CRAWLER_OPTIONS gs_sOptions = { 0 };
static PLDAP_ROOT_DSE gs_pRootDse = NULL;
static PLONG gs_plSucceededRequestsCount = NULL;

static const DIR_CRAWLER_LDAP_CONTROL_DESCRIPTION gsc_asAlwaysOnCtrlsList[] = {
    // NOTE: Control 'LDAP_SERVER_SHOW_DELETED_OID' is useless here (redundant with 'LDAP_SERVER_SHOW_RECYCLED_OID')
    // but still specified in case of the latter is not supported by the server
    {
        .ptName = STR(LDAP_SERVER_SHOW_RECYCLED_OID),
        .ptOid = LDAP_SERVER_SHOW_RECYCLED_OID_W,
        .eCtrlType = DirCrawlerLdapCtrlServer,
        .bHasValue = FALSE
    },
    {
        .ptName = STR(LDAP_SERVER_SHOW_DELETED_OID),
        .ptOid = LDAP_SERVER_SHOW_DELETED_OID_W,
        .eCtrlType = DirCrawlerLdapCtrlServer,
        .bHasValue = FALSE
    },
    {
        .ptName = STR(LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID),
        .ptOid = LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID_W,
        .eCtrlType = DirCrawlerLdapCtrlServer,
        .bHasValue = FALSE
    }
};

/* --- PUBLIC VARIABLES ----------------------------------------------------- */
PUTILS_HEAP g_pDirCrawlerHeap = NULL;

/* --- PRIVATE FUNCTIONS ---------------------------------------------------- */
__declspec(noreturn) static void DirCrawlerUsage(
    _In_ const PTCHAR ptProgName,
    _In_opt_ const PTCHAR ptMsg
    ) {
    if (ptMsg != NULL) {
        LOG(Err, _T("Error: %s"), ptMsg);
    }
    LOG(Bypass, _T("Usage: %s <ldap options> <dump options> <misc options>"), ptProgName);

    LOG(Bypass, _T("Ldap options:"));
    LOG(Bypass, SUB_LOG(_T("-s <server>  : ldap server to dump information from")));
    LOG(Bypass, SUB_LOG(_T("-l <username>: AD username for explicit authentification")));
    LOG(Bypass, SUB_LOG(_T("-p <password>: AD password for explicit authentification")));
    LOG(Bypass, SUB_LOG(_T("-n <port>    : ldap port (default: <%u>)")), LDAP_DEFAULT_PORT);
    LOG(Bypass, SUB_LOG(_T("-d <dns name>: explicit domain dns name (default: resolved dynamically)")));

    LOG(Bypass, _T("Dump options:"));
    LOG(Bypass, SUB_LOG(_T("-j <jsonfile> : JSON file containing LDAP requests description")));
    LOG(Bypass, SUB_LOG(_T("-o <outputdir>: Output directory")));
    LOG(Bypass, SUB_LOG(_T("-r <requests> : Sublist of requests names in the json file (comma separated)")));

    LOG(Bypass, _T("Misc options:"));
    LOG(Bypass, SUB_LOG(_T("-h/H         : Show this help")));
    LOG(Bypass, SUB_LOG(_T("-t <num>     : Number of threads to use (default: number of core, must be <= MAXIMUM_WAIT_OBJECTS (%u))")), MAXIMUM_WAIT_OBJECTS);
    LOG(Bypass, SUB_LOG(_T("-c <prefix>  : Prefix outfiles with an arbitrary value (default: 2 first chars of domain name)")));
    LOG(Bypass, SUB_LOG(_T("-v <level>   : Set console log level. Possibles values are <ALL,DBG,INFO,WARN,ERR,SUCC,NONE>")));
    LOG(Bypass, SUB_LOG(_T("-w <level>   : Set logfile log level (default: same as console log level)")));
    LOG(Bypass, SUB_LOG(_T("-f <logfile> : Log file name (default is none)")));

    ExitProcess(EXIT_FAILURE);
}

static void DirCrawlerParseOptions(
    _In_ const PDIR_CRAWLER_OPTIONS pOpt,
    _In_ const int argc,
    _In_ const PTCHAR argv[]
    ) {
    int curropt = 0;
    PTCHAR ptSlashInLogin = NULL;
    PTCHAR ptReq = NULL;
    PTCHAR ptCtx = NULL;
    SYSTEM_INFO sSystemInfo = { 0 };
    BOOL bLogLevelFileSet = FALSE;

    GetSystemInfo(&sSystemInfo);

    pOpt->ldap.dwLdapPort = LDAP_DEFAULT_PORT;
    pOpt->log.ptLogLevelConsole = DEFAULT_OPT_LOG_LEVEL;
    pOpt->log.ptLogLevelFile = DEFAULT_OPT_LOG_LEVEL;
    pOpt->misc.dwMaxThreads = sSystemInfo.dwNumberOfProcessors;

    while ((curropt = getopt(argc, argv, _T("s:l:p:n:d:j:o:r:t:c:v:w:f:Hh"))) != -1) {
        switch (curropt) {

        case _T('s'): pOpt->ldap.ptLdapServer = optarg; break;
        case _T('l'): pOpt->ldap.ptLogin = optarg; break;
        case _T('p'): pOpt->ldap.ptPassword = optarg; break;
        case _T('n'): pOpt->ldap.dwLdapPort = _tstoi(optarg); break;
        case _T('d'): pOpt->ldap.ptDnsName = optarg; break;

        case _T('j'): pOpt->dump.ptJsonFile = optarg; break;
        case _T('o'): pOpt->dump.ptOutputDir = optarg; break;
        case _T('r'): pOpt->dump.ptRequestSublist = optarg; break;

        case _T('h'):
        case _T('H'): pOpt->misc.bShowHelp = TRUE; break;
        case _T('t'): pOpt->misc.dwMaxThreads = _tstoi(optarg); break;
        case _T('c'): pOpt->misc.ptOutfilesPrefix = optarg; break;
        case _T('v'): pOpt->log.ptLogLevelConsole = optarg; break;
        case _T('w'): pOpt->log.ptLogLevelFile = optarg; bLogLevelFileSet = TRUE; break;
        case _T('f'): pOpt->log.ptLogFile = optarg; break;

        default:
            FATAL(_T("Unknown option <%u>"), curropt);
        }
    }

    if (pOpt->ldap.ptLogin != NULL) {
        ptSlashInLogin = _tcschr(pOpt->ldap.ptLogin, _T('\\'));
        if (ptSlashInLogin != NULL) { // userName actually starts with the domain name (ex: DOMAIN\username)
            *ptSlashInLogin = 0;
            pOpt->ldap.ptExplicitDomain = pOpt->ldap.ptLogin;
            pOpt->ldap.ptLogin = ptSlashInLogin + 1;
        }
    }

    if (pOpt->dump.ptRequestSublist != NULL) {
        while (StrNextToken(pOpt->dump.ptRequestSublist, _T(","), &ptCtx, &ptReq)) {
            pOpt->dump.requests.dwCount += 1;
            pOpt->dump.requests.pptList = UtilsHeapAllocOrReallocHelper(g_pDirCrawlerHeap, pOpt->dump.requests.pptList, SIZEOF_ARRAY(PTCHAR, pOpt->dump.requests.dwCount));
            pOpt->dump.requests.pptList[pOpt->dump.requests.dwCount - 1] = ptReq;
        }
    }

    if (bLogLevelFileSet == FALSE) {
        pOpt->log.ptLogLevelFile = pOpt->log.ptLogLevelConsole;
    }

    if (pOpt->misc.bShowHelp) {
        DirCrawlerUsage(argv[0], NULL);
    }
}

static void DirCrawlerSetDefaultPrefix(
    _In_ const PDIR_CRAWLER_OPTIONS pOpt,
    _In_ const PLDAP_ROOT_DSE pRootDse
    ) {
    static TCHAR s_atDefaultPrefix[3] = { 0 };
    PTCHAR ptDomDnsName = pOpt->ldap.ptDnsName != NULL ? pOpt->ldap.ptDnsName : pRootDse->extracted.ptLdapServiceName;

    if (ptDomDnsName == NULL) {
        FATAL(_T("Failed to automatically retrieve domain DNS name, and none was explicitely specified"));
    }

    s_atDefaultPrefix[0] = (TCHAR)_totupper(ptDomDnsName[0]);
    s_atDefaultPrefix[1] = (TCHAR)_totupper(ptDomDnsName[1]);
    s_atDefaultPrefix[2] = NULL_CHAR;

    pOpt->misc.ptOutfilesPrefix = s_atDefaultPrefix; // Used only here, only once, with only one possible destination, so not a problem.
}

PTCHAR DirCrawlerComputeOutputRootFolderName(
   ) {
   PTCHAR tFormatedOutput = NULL;
   DWORD dwFormatedOutputLen = 0;
   SYSTEMTIME sSystemTime = { 0 };
   INT dwRes = 0;
   PTCHAR tDomainFQDN = gs_sOptions.ldap.ptDnsName;

   if (tDomainFQDN == NULL) {
      FATAL(_T("Unable to retrieve DNS domain name. Please provide it in the cmdline."));
   }

   GetSystemTime(&sSystemTime);

   dwFormatedOutputLen = (DWORD)(4 + 2 + 2 + 1 + _tcslen(tDomainFQDN)); // Year + Month + Day + _ +FQDN
   tFormatedOutput = (PTCHAR)UtilsHeapAllocArrayHelper(g_pDirCrawlerHeap, PTCHAR, dwFormatedOutputLen + 1);

   dwRes = _stprintf_s(tFormatedOutput, (size_t) (dwFormatedOutputLen + 1), TEXT("%u"), sSystemTime.wYear);
   if (dwRes == -1) {
      FATAL(_T("Unable to call _stprintf_s (1)."));
   }

   if (sSystemTime.wMonth < 10)
      dwRes = _stprintf_s(tFormatedOutput, (size_t) (dwFormatedOutputLen + 1), TEXT("%ws0%u"), tFormatedOutput, sSystemTime.wMonth);
   else
      dwRes = _stprintf_s(tFormatedOutput, (size_t) (dwFormatedOutputLen + 1), TEXT("%ws%u"), tFormatedOutput, sSystemTime.wMonth);
   if (dwRes == -1) {
      FATAL(_T("Unable to call _stprintf_s (2)."));
   }

   if (sSystemTime.wDay < 10)
      dwRes = _stprintf_s(tFormatedOutput, (size_t) (dwFormatedOutputLen + 1), TEXT("%ws0%u"), tFormatedOutput, sSystemTime.wDay);
   else
      dwRes = _stprintf_s(tFormatedOutput, (size_t) (dwFormatedOutputLen + 1), TEXT("%ws%u"), tFormatedOutput, sSystemTime.wDay);
   if (dwRes == -1) {
      FATAL(_T("Unable to call _stprintf_s (3)."));
   }

   dwRes = _stprintf_s(tFormatedOutput, (size_t) (dwFormatedOutputLen + 1), TEXT("%ws_%ws"), tFormatedOutput, tDomainFQDN);
   if (dwRes == -1) {
      FATAL(_T("Unable to call _stprintf_s (4)."));
   }

   return tFormatedOutput;
}

static BOOL DirCrawlerFormatOutfile(
    _Inout_ const PTCHAR ptOutFileName, // Must be able to receive MAX_PATH chars
    _In_ const PTCHAR ptOutputDirName,
   _In_ const PTCHAR ptOutputFolderName,
    _In_ const PTCHAR ptFilePrefix,
    _In_ const PTCHAR ptFileNameElmt1,
    _In_opt_ const PTCHAR ptFileNameElmt2,
    _In_ const PTCHAR ptFileExtension
    ) {
    int size = -1;
    PTCHAR ptRootFolderName = DirCrawlerComputeOutputRootFolderName();

    if (ptFileNameElmt2 != NULL) {
        size = _stprintf_s(ptOutFileName, MAX_PATH, _T("%s\\%s\\%s\\%s_%s_%s.%s"), ptOutputDirName, ptRootFolderName, ptOutputFolderName, ptFilePrefix, ptFileNameElmt1, ptFileNameElmt2, ptFileExtension);
    }
    else {
        size = _stprintf_s(ptOutFileName, MAX_PATH, _T("%s\\%s\\%s\\%s_%s.%s"), ptOutputDirName, ptRootFolderName, ptOutputFolderName, ptFilePrefix, ptFileNameElmt1, ptFileExtension);
    }

    if (ptRootFolderName) {
       UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, ptRootFolderName);
    }
    return (BOOL)(size != -1);
}

static PTCHAR DirCrawlerGetBindingNc(
    _In_ const PLDAP_ROOT_DSE pRootDse,
    _In_ const PDIR_CRAWLER_REQ_DESCR pReqDescr
    ) {
    switch (pReqDescr->ldap.base.eType) {
    case DirCrawlerLdapBaseDN:
        return pReqDescr->ldap.base.value.ptBaseDN;
    case DirCrawlerLdapBaseNcShortcut:
        switch (pReqDescr->ldap.base.value.eBaseNcShortcut) {
        case DirCrawlerLdapNcDomain:
            return pRootDse->extracted.ptDefaultNamingContext;
        case DirCrawlerLdapNcConfiguration:
            return pRootDse->extracted.ptConfigurationNamingContext;
        case DirCrawlerLdapNcSchema:
            return pRootDse->extracted.ptSchemaNamingContext;
            /* TODO: les NC de zones DNS ne sont pas enregistrées dans un attribut spécifique => rajouter un index dans pNamingContexts comme attributs computed */
        case DirCrawlerLdapNcDomainDnsZones: FATAL(_T("DirCrawlerLdapNcDomainDnsZones NOT IMPLEMENTED"));
        case DirCrawlerLdapNcForestDnsZones: FATAL(_T("DirCrawlerLdapNcForestDnsZones NOT IMPLEMENTED"));
        default:
            REQ_FATAL(pReqDescr, _T("Invalid LDAP base shortcut value: <%u>"), pReqDescr->ldap.base.value.eBaseNcShortcut);
        }
    case DirCrawlerLdapBaseWildcardAll:
        REQ_FATAL(pReqDescr, _T("Trying to resolve a wildcard '*' to an LDAP base NC"), pReqDescr->ldap.base.eType);
    default:
        REQ_FATAL(pReqDescr, _T("Invalid LDAP base type value: <%u>"), pReqDescr->ldap.base.eType);
    }

    return NULL;
}

static BOOL DirCrawlerAddControlsArray(
    _In_ const PDIR_CRAWLER_REQ_DESCR pReqDescr,
    _In_ const DIR_CRAWLER_LDAP_CONTROL_DESCRIPTION * const pCtrlsList,
    _In_ const DWORD dwCtrlsCount,
    _Inout_ PLDAPControl *pppClientCtrlsList[],
    _Inout_ PLDAPControl *pppServerCtrlsList[],
    _Inout_ PDWORD pdwClientCtrlsCount,
    _Inout_ PDWORD pdwServerCtrlsCount,
    _In_ const BOOL bFailIfNotSupported
    ) {
    PLDAPControl *ppCurrentLdapCtrl = NULL;
    BerElement *pBerElmt = NULL;
    PBERVAL pBerVal = NULL;
    INT iRet = -1;
    DWORD i = 0;

    for (i = 0; i < dwCtrlsCount; i++) {

        if (IsInSetOfStrings(pCtrlsList[i].ptOid, gs_pRootDse->extracted.pptSupportedControl, gs_pRootDse->computed.count.dwSupportedControlCount, NULL) == FALSE) {
            if (bFailIfNotSupported == TRUE) {
                REQ_FATAL(pReqDescr, _T("Using a non-supported LDAP control <%s:%s>"), pCtrlsList[i].ptName, pCtrlsList[i].ptOid);
            }
            else {
                REQ_LOG(pReqDescr, Err, _T("Using a non-supported LDAP control <%s:%s>"), pCtrlsList[i].ptName, pCtrlsList[i].ptOid);
            }
        }
        else {
            switch (pCtrlsList[i].eCtrlType) {
            case DirCrawlerLdapCtrlClient:
                (*pdwClientCtrlsCount) += 1;
                (*pppClientCtrlsList) = UtilsHeapAllocOrReallocHelper(g_pDirCrawlerHeap, (*pppClientCtrlsList), SIZEOF_ARRAY(PLDAPControl, (*pdwClientCtrlsCount) + 1)); // +1 because it needs to be NULL terminated
                ppCurrentLdapCtrl = &(*pppClientCtrlsList)[(*pdwClientCtrlsCount) - 1];
                break;
            case DirCrawlerLdapCtrlServer:
                (*pdwServerCtrlsCount) += 1;
                (*pppServerCtrlsList) = UtilsHeapAllocOrReallocHelper(g_pDirCrawlerHeap, (*pppServerCtrlsList), SIZEOF_ARRAY(PLDAPControl, (*pdwServerCtrlsCount) + 1)); // +1 because it needs to be NULL terminated
                ppCurrentLdapCtrl = &(*pppServerCtrlsList)[(*pdwServerCtrlsCount) - 1];
                break;
            default:
                REQ_FATAL(pReqDescr, _T("Invalid control type <%u> for control <%s>"), pCtrlsList[i].eCtrlType, pCtrlsList[i].ptName);
            }

            (*ppCurrentLdapCtrl) = UtilsHeapAllocStructHelper(g_pDirCrawlerHeap, LDAPControl);
            (*ppCurrentLdapCtrl)->ldctl_iscritical = TRUE;
            (*ppCurrentLdapCtrl)->ldctl_oid = pCtrlsList[i].ptOid;
            (*ppCurrentLdapCtrl)->ldctl_value.bv_len = 0;
            (*ppCurrentLdapCtrl)->ldctl_value.bv_val = NULL;

            if (pCtrlsList[i].bHasValue == TRUE) {
                pBerElmt = ber_alloc_t(LBER_USE_DER);
                if (pBerElmt == NULL) {
                    REQ_FATAL(pReqDescr, _T("Failed to alloc BER-value for LDAP control <%s:%s>"), pCtrlsList[i].ptOid, pCtrlsList[i].ptName);
                }

                switch (pCtrlsList[i].eValueType) {
                case DirCrawlerTypeStr:
                    WARN_UNTESTED(_T("control value of type 'string'"));
                    iRet = ber_printf(pBerElmt, "{s}", pCtrlsList[i].value.ptVal); // TODO : non testé. bon format ? unicode ?
                    break;
                case DirCrawlerTypeInt:
                    iRet = ber_printf(pBerElmt, "{i}", pCtrlsList[i].value.iVal);
                    break;
                case DirCrawlerTypeBin:
                    REQ_FATAL(pReqDescr, _T("NOT IMPLEMENTED: BER encoding of 'DirCrawlerTypeBin' values is not yet implemented")); //TODO : non implémenté
                }
                if (iRet == -1) {
                    REQ_FATAL(pReqDescr, _T("Failed to BER-encode value for LDAP control <%s:%s>"), pCtrlsList[i].ptOid, pCtrlsList[i].ptName);
                }

                iRet = ber_flatten(pBerElmt, &pBerVal);
                if (iRet == -1) {
                    REQ_FATAL(pReqDescr, _T("Failed to flatten BER-value for LDAP control <%s:%s>"), pCtrlsList[i].ptOid, pCtrlsList[i].ptName);
                }

                (*ppCurrentLdapCtrl)->ldctl_value.bv_len = pBerVal->bv_len;
                (*ppCurrentLdapCtrl)->ldctl_value.bv_val = UtilsHeapMemDupHelper(g_pDirCrawlerHeap, pBerVal->bv_val, pBerVal->bv_len);

                ber_bvfree(pBerVal);
                ber_free(pBerElmt, 1);
            }
        }
    }

    return TRUE;
}

static void DirCrawlerDestroyControlArray(
    _Inout_ PLDAPControl *pppCtrlsList[]
    ) {
    DWORD i = 0;

    if ((*pppCtrlsList) != NULL) {
        for (i = 0; (*pppCtrlsList)[i] != NULL; i++) {
            UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, (*pppCtrlsList)[i]->ldctl_value.bv_val);
            UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, (*pppCtrlsList)[i]);
        }
        UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, (*pppCtrlsList));
    }
}

static BOOL DirCrawlerCreateAttributesArray(
    _In_ const PDIR_CRAWLER_REQ_DESCR pReqDescr,
    _Out_ PDIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION *ppptAttrsList[],
    _Out_ PDWORD pdwAttrsCount
    ) {
    DWORD i = 0;

    (*ppptAttrsList) = UtilsHeapAllocArrayHelper(g_pDirCrawlerHeap, PDIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION, pReqDescr->ldap.attributes.dwAttrCount + 1); // +1 because it always starts with DN
    (*pdwAttrsCount) = pReqDescr->ldap.attributes.dwAttrCount + 1;
    ((*ppptAttrsList)[0]) = UtilsHeapAllocHelper(g_pDirCrawlerHeap, sizeof(DIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION));
    ((*ppptAttrsList)[0])->ptName = UtilsHeapStrDupHelper(g_pDirCrawlerHeap, LDAP_ATTR_DISTINGUISHED_NAME);

    for (i = 0; i < (*pdwAttrsCount) - 1 ; i++) {
        ((*ppptAttrsList)[i + 1]) = UtilsHeapAllocHelper(g_pDirCrawlerHeap, sizeof(DIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION));
        ((*ppptAttrsList)[i + 1])->ptName = UtilsHeapStrDupHelper(g_pDirCrawlerHeap, pReqDescr->ldap.attributes.pAttrArray[i].ptName);
        ((*ppptAttrsList)[i + 1])->eType = pReqDescr->ldap.attributes.pAttrArray[i].eType;
    }

    return TRUE;
}

static PTCHAR DirCrawlerStringifyAttribute(
    _In_ const PLDAP_ATTRIBUTE pLdapAttribute,
    _In_ const PDIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION pAttrDesc
    ) {
    DWORD i = 0;
    DWORD dwLen = 0;
    LPSTR pOutBuff = NULL;
    LPSTR pCurrentBuff = NULL;
    PFN_LDAP_ATTR_VALUE_FORMATTER pfnFormatter = gc_ppfnFormatters[pAttrDesc->eType];
    DWORD szMbBuffer = 0;
    LPWSTR lpwOutBuff = NULL;

    for (i = 0; i < pLdapAttribute->dwValuesCount; i++) {
        dwLen += pfnFormatter(pLdapAttribute->ppValues[i], NULL); // NULL as buffer == only return the required len
        dwLen += 1; // attribute values separator
    }

    pOutBuff = UtilsHeapAllocStrHelper(g_pDirCrawlerHeap, dwLen);
    pCurrentBuff = pOutBuff;

    for (i = 0; i < pLdapAttribute->dwValuesCount; i++) {
        pCurrentBuff += pfnFormatter(pLdapAttribute->ppValues[i], pCurrentBuff);
        *(pCurrentBuff - 1) = (i == pLdapAttribute->dwValuesCount - 1 ? NULL_CHAR : DIR_CRAWLER_LDAP_VAL_SEPARATOR);
    }

#ifdef UNICODE
    szMbBuffer = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (LPCCH)pOutBuff, -1, NULL, 0);
    lpwOutBuff = UtilsHeapAllocStrHelper(g_pDirCrawlerHeap, szMbBuffer * sizeof(TCHAR));
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (LPCCH)pOutBuff, -1, lpwOutBuff, szMbBuffer);
    UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pOutBuff);
    return lpwOutBuff;
#else
    return pOutBuff;
#endif
}

static PTCHAR DirCrawlerFormatAttribute(
    _In_ const PLDAP_CONNECT pLdapConnect,
    _In_ const PLDAP_ENTRY pLdapEntry,
    _In_ const PDIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION pAttrDesc
    ) {
    BOOL bResult = FALSE;
    PLDAP_ATTRIBUTE pDuplicatedAttribute = NULL;
    PTCHAR ptFormatted = NULL;

    bResult = LdapDupNamedAttr(pLdapConnect, pLdapEntry, pAttrDesc->ptName, &pDuplicatedAttribute);
    if (bResult == TRUE && pDuplicatedAttribute->dwValuesCount > 0) {
        ptFormatted = DirCrawlerStringifyAttribute(pDuplicatedAttribute, pAttrDesc);
    }
    else {
        ptFormatted = UtilsHeapStrDupHelper(g_pDirCrawlerHeap, EMPTY_STR);
    }

    if (pDuplicatedAttribute != NULL) {
        LdapReleaseAttribute(pLdapConnect, &pDuplicatedAttribute);
    }
    return ptFormatted;
}

static BOOL DirCrawlerWriteLdapEntryToTsvOutfile(
    _In_ const CSV_HANDLE hCsvOutfile,
    _In_ const PLDAP_CONNECT pLdapConnect,
    _In_ const PLDAP_ENTRY pLdapEntry,
    _In_ const PDIR_CRAWLER_REQ_DESCR pReqDescr
    ) {
    PTCHAR *pptCsvRecord = NULL;
    BOOL bResult = FALSE;
    DWORD i = 0;
    DWORD dwAttrCount = pReqDescr->ldap.attributes.dwAttrCount;
    DWORD dwCsvHeaderCount = 0;

    // Format attributes
    pptCsvRecord = UtilsHeapAllocArrayHelper(g_pDirCrawlerHeap, PTCHAR, dwAttrCount + 1); // +1 for the DN
    pptCsvRecord[0] = pLdapEntry->ptDn;

    for (i = 0; i < dwAttrCount; i++) {
        pptCsvRecord[i + 1] = DirCrawlerFormatAttribute(pLdapConnect, pLdapEntry, &pReqDescr->ldap.attributes.pAttrArray[i]);
        if (pptCsvRecord[i + 1] == NULL) {
            REQ_FATAL(pReqDescr, _T("Failed to format attribute <%s> of entry <%s>"), pReqDescr->ldap.attributes.pAttrArray[i].ptName, pLdapEntry->ptDn);
        }
    }

    // Retrieve expected csv column count and compare it with record count
    bResult = CsvGetHeaderNumberOfFields(hCsvOutfile, &dwCsvHeaderCount);
    if (API_FAILED(bResult)) {
       REQ_FATAL(pReqDescr, _T("Failed to retrieve header fields count for current CSV : <err:%#08x>"), CsvGetLastError(hCsvOutfile));
    }
    if (dwCsvHeaderCount != (dwAttrCount + 1)) {
       REQ_FATAL(pReqDescr, _T("Incoherent record count : excepted %d records but %d provided."), dwCsvHeaderCount, (dwAttrCount + 1));
    }

    // Write CSV record
    bResult = CsvWriteNextRecord(hCsvOutfile, pptCsvRecord, NULL);
    if (API_FAILED(bResult)) {
        REQ_FATAL(pReqDescr, _T("Failed to write csv record for entry <%s>: <err:%#08x>"), pLdapEntry->ptDn, CsvGetLastError(hCsvOutfile));
    }

    // Cleanup
    for (i = 0; i < dwAttrCount; i++) {
        UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pptCsvRecord[i + 1]);
    }
    UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pptCsvRecord);

    return TRUE;
}

static DWORD DirCrawlerBindAndSearch(
    _In_ const PDIR_CRAWLER_REQ_DESCR pReqDescr,
    _In_ const CSV_HANDLE hCsvOutfile,
    _In_ const PTCHAR pptAttrsList[],
    _In_ const PLDAP_CONNECT pLdapConnect,
    _In_ const PLDAP_OPTIONS pLdapOptions,
    _In_ const PTCHAR ptLdapBindingNc,
    _In_ PLDAPControl ppClientCtrlsList[],
    _In_ PLDAPControl ppServerCtrlsList[]
    ) {
    BOOL bResult = FALSE;
    PLDAP_REQUEST pLdapRequest = NULL;
    PLDAP_ENTRY pLdapEntry = NULL;
    DWORD dwEntryCount = 0;
    BOOL bLdapNoMoreEntries = FALSE;

    // Ldap Bind
    bResult = LdapBind(pLdapConnect, ptLdapBindingNc, pLdapOptions->ptLogin, pLdapOptions->ptPassword, pLdapOptions->ptExplicitDomain);
    if (!bResult) {
        REQ_FATAL(pReqDescr, _T("Failed to bind to ldap server: <err:%#08x>"), LdapLastError());
    }

    // Ldap Search
    bResult = LdapInitRequestEx(pLdapConnect, ptLdapBindingNc, pReqDescr->ldap.ptFilter, pReqDescr->ldap.eScope, pptAttrsList, ppServerCtrlsList, ppClientCtrlsList, &pLdapRequest);
    if (API_FAILED(bResult)) {
        REQ_FATAL(pReqDescr, _T("Failed to init ldap request <%s> on <%s>: <err:%#08x>"), pReqDescr->ldap.ptFilter, ptLdapBindingNc, LdapLastError());
    }

    // Parse Results
    while (bLdapNoMoreEntries == FALSE) {
        bResult = LdapGetNextEntry(pLdapConnect, pLdapRequest, &pLdapEntry);
        if (API_FAILED(bResult)) {
            REQ_FATAL(pReqDescr, _T("Unable to get next LDAP entry <%u>: <err:%#08x>"), dwEntryCount, LdapLastError());
        }
        if (pLdapEntry == NULL) {
            bLdapNoMoreEntries = TRUE;
        }
        else {
            dwEntryCount++;

            if (pLdapEntry->dwAttributesCount != pLdapRequest->dwRequestedAttrCount) {
                REQ_FATAL(pReqDescr, _T("Wrong count of retreived attributes for <%s>: <%u/%u>"), pLdapEntry->ptDn, pLdapEntry->dwAttributesCount, pLdapRequest->dwRequestedAttrCount);
            }
            bResult = DirCrawlerWriteLdapEntryToTsvOutfile(hCsvOutfile, pLdapConnect, pLdapEntry, pReqDescr);
            if (bResult == FALSE) {
                REQ_FATAL(pReqDescr, _T("Failed to write entry <%s>"), pLdapEntry->ptDn);
            }

            LdapReleaseEntry(pLdapConnect, &pLdapEntry);
        }
    }

    // Cleanup
    LdapReleaseRequest(pLdapConnect, &pLdapRequest);

    return dwEntryCount;
}

static void DirCrawlerProcessLdapRequest(
    _In_ const PDIR_CRAWLER_REQ_DESCR pReqDescr,
    _In_ const PDIR_CRAWLER_OPTIONS pOptions,
    _In_ const PLDAP_ROOT_DSE pLdapRootDse
    ) {
    BOOL bResult = FALSE;
    DWORD dwResultCount = 0;
    PTCHAR ptLdapBindingNc = NULL;
    PLDAP_CONNECT pLdapConnect = NULL;
    TCHAR atOutFileName[MAX_PATH] = { 0 };
    CSV_HANDLE hCsvOutfile = CSV_INVALID_HANDLE_VALUE;
    PDIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION *pptAttrsList = { 0 };
    PTCHAR *pptAttrsListForLdap = { 0 };
    PTCHAR *pptAttrsListForCsv = { 0 };
    DWORD dwAttrsCount = 0;
    DWORD i = 0;
    PLDAPControl * ppClientCtrlsList = NULL;
    PLDAPControl * ppServerCtrlsList = NULL;
    DWORD dwClientCtrlsCount = 0;
    DWORD dwServerCtrlsCount = 0;
    ULONGLONG ullTimeStart = GetTickCount64();

    REQ_LOG(pReqDescr, Info, _T("Starting request: <%s>"), pReqDescr->infos.ptDescription);

    // Create parameters (outfile, controls, attributes, ...)
    bResult = DirCrawlerFormatOutfile(atOutFileName, pOptions->dump.ptOutputDir, DIR_CRAWLER_OUTPUT_DIR, pOptions->misc.ptOutfilesPrefix, DIR_CRAWLER_OUTFILES_KEYWORD, pReqDescr->infos.ptName, DIR_CRAWLER_OUTFILES_EXT);
    if (bResult == FALSE) {
        REQ_FATAL(pReqDescr, _T("Failed to format outfile path"));
    }

    bResult = DirCrawlerCreateAttributesArray(pReqDescr, &pptAttrsList, &dwAttrsCount);
    if (bResult == FALSE) {
        REQ_FATAL(pReqDescr, _T("Failed to create attribute list"));
    }
    pptAttrsListForCsv = UtilsHeapAllocArrayHelper(g_pDirCrawlerHeap, PTCHAR, dwAttrsCount + 1); // Apparently LdapLib needs a final NULL...
    for (i = 0; i < dwAttrsCount ; i++) {
        pptAttrsListForCsv[i] = UtilsHeapStrDupHelper(g_pDirCrawlerHeap,pptAttrsList[i]->ptName);
    }
    pptAttrsListForCsv[dwAttrsCount] = NULL;
    pptAttrsListForLdap = &pptAttrsListForCsv[1]; // skip 'DN' for the LDAP request
    pptAttrsList = &pptAttrsList[1];

    bResult = DirCrawlerAddControlsArray(pReqDescr, gsc_asAlwaysOnCtrlsList, _countof(gsc_asAlwaysOnCtrlsList), &ppClientCtrlsList, &ppServerCtrlsList, &dwClientCtrlsCount, &dwServerCtrlsCount, FALSE);
    if (bResult == FALSE) {
        REQ_FATAL(pReqDescr, _T("Failed to add always-on controls to control list"));
    }

    bResult = DirCrawlerAddControlsArray(pReqDescr, pReqDescr->ldap.controls.pCtrlArray, pReqDescr->ldap.controls.dwCtrlCount, &ppClientCtrlsList, &ppServerCtrlsList, &dwClientCtrlsCount, &dwServerCtrlsCount, TRUE);
    if (bResult == FALSE) {
        REQ_FATAL(pReqDescr, _T("Failed to add request-specific controls to control list"));
    }

    // Open Csv outfile
    bResult = CsvOpenWrite(atOutFileName, dwAttrsCount, pptAttrsListForCsv, &hCsvOutfile); // +1 for the DN
    if (API_FAILED(bResult)) {
        REQ_FATAL(pReqDescr, _T("Failed to open CSV outfile <%s>: <err:%#08x>"), atOutFileName, CsvGetLastError(hCsvOutfile));
    }

    // Ldap Connect
    bResult = LdapConnect(pOptions->ldap.ptLdapServer, pOptions->ldap.dwLdapPort, &pLdapConnect, NULL);
    if (!bResult) {
        REQ_FATAL(pReqDescr, _T("Failed to connect to ldap server: <err:%#08x>"), LdapLastError());
    }

    // Ldap Bind
    if (pReqDescr->ldap.base.eType != DirCrawlerLdapBaseWildcardAll) {
        ptLdapBindingNc = DirCrawlerGetBindingNc(pLdapRootDse, pReqDescr);
        dwResultCount = DirCrawlerBindAndSearch(pReqDescr, hCsvOutfile, pptAttrsListForLdap, pLdapConnect, &pOptions->ldap, ptLdapBindingNc, ppClientCtrlsList, ppServerCtrlsList);
    }
    else {
        for (i = 0; i < pLdapRootDse->computed.count.dwNamingContextsCount; i++) {
            dwResultCount += DirCrawlerBindAndSearch(pReqDescr, hCsvOutfile, pptAttrsListForLdap, pLdapConnect, &pOptions->ldap, pLdapRootDse->extracted.pptNamingContexts[i], ppClientCtrlsList, ppServerCtrlsList);
        }
    }

    // Cleanup & close
    UtilsHeapFreeAndNullArrayHelper(g_pDirCrawlerHeap, pptAttrsListForCsv, dwAttrsCount, i);
    DirCrawlerDestroyControlArray(&ppServerCtrlsList);
    DirCrawlerDestroyControlArray(&ppClientCtrlsList);
    LdapCloseConnection(&pLdapConnect, NULL);
    CsvClose(&hCsvOutfile);

    REQ_LOG(pReqDescr, Succ, _T("<count:%u> <time:%.3fs>"), dwResultCount, TIME_DIFF_SEC(ullTimeStart, GetTickCount64()));
}

static BOOL DirCrawlerCreateFolderRecursively(
   _In_ PTCHAR tFolderToCreateOnFS
   ) {
   TCHAR tFolder[MAX_PATH];
   PTCHAR ptEnd;
   DWORD dwErr = 0, dwLen = 0, dwRes = 0;

   ZeroMemory(tFolder, MAX_PATH * sizeof(TCHAR));
   ptEnd = wcschr(tFolderToCreateOnFS, L'\\');

   while (ptEnd != NULL)
   {
      dwLen = (DWORD)(ptEnd - tFolderToCreateOnFS + 1);
      _tcsncpy_s(tFolder, MAX_PATH, tFolderToCreateOnFS, dwLen);

      if ((_tcsclen(tFolder) == 2) && (_tcsncmp(tFolder, TEXT(".\\"), 2) == 0))
         goto continue_loop;

      dwRes = GetFileAttributes(tFolder);
      if ((dwRes == INVALID_FILE_ATTRIBUTES) || (dwRes & FILE_ATTRIBUTE_DIRECTORY)) {
         goto continue_loop;
      }

      if (!CreateDirectory(tFolder, NULL))
      {
         dwErr = GetLastError();
         if (dwErr != ERROR_ALREADY_EXISTS) {
            FATAL(_T("Unable to create folder recursively."));
         }
      }
   continue_loop:
      ptEnd = _tcschr(++ptEnd, L'\\');
   }

   _tcsncpy_s(tFolder, MAX_PATH, tFolderToCreateOnFS, _tcslen(tFolderToCreateOnFS));
   if (!CreateDirectory(tFolder, NULL))
   {
      dwErr = GetLastError();
      if (dwErr != ERROR_ALREADY_EXISTS) {
         FATAL(_T("Unable to create folder recursively."));
      }
   }

   return TRUE;
}

DWORD WINAPI DirCrawlerDoRequests(
    LPVOID lpThreadParameter
    ) {
    UNREFERENCED_PARAMETER(lpThreadParameter);

    PSLIST_ENTRY pListEntry = NULL;
    PDIR_CRAWLER_REQ_LIST_ENTRY pReqListEntry = NULL;

    while ((pListEntry = InterlockedPopEntrySList(gs_pReqListHead)) != NULL) {
        pReqListEntry = CONTAINING_RECORD(pListEntry, DIR_CRAWLER_REQ_LIST_ENTRY, sListEntry);
        REQ_LOG(pReqListEntry->pReqDescr, Dbg, _T("<thread:%#08x>"), GetCurrentThreadId());

        __try {
            DirCrawlerProcessLdapRequest(pReqListEntry->pReqDescr, &gs_sOptions, gs_pRootDse);
            InterlockedIncrement(gs_plSucceededRequestsCount);
        }
#pragma warning(suppress: 6320)
        __except (EXCEPTION_EXECUTE_HANDLER) {
            REQ_LOG(pReqListEntry->pReqDescr, Err, _T("Abnormal termination"));
        }

        _aligned_free(pReqListEntry);
    }

    LOG(Dbg, _T("Exiting <thread:%#08x>"), GetCurrentThreadId());
    return EXIT_SUCCESS;
}

/* --- PUBLIC FUNCTIONS ----------------------------------------------------- */
int _tmain(
    _In_ const int argc,
    _In_ const PTCHAR argv[]
    ) {
    //
    // Variables
    //
    BOOL bResult = FALSE;
    BOOL globalSuccess = FALSE;
    DWORD dwResult = 0;
    DWORD i = 0;
    DWORD dwSentReqCount = 0;
    PLDAP_CONNECT pConnection = NULL;
    DIR_CRAWLER_REQ_DESCR_ARRAY sRequestsDescriptions = { 0 };
    ULONGLONG ullTimeStart = GetTickCount64();
    HANDLE *phThreads = NULL;
    PDIR_CRAWLER_REQ_LIST_ENTRY pReqListEntry = NULL;
    PTCHAR ptRootFolderName = NULL;
    TCHAR ptRootFolderPath[MAX_PATH] = { 0 };
    TCHAR ptDefaultResultsFolderPath[MAX_PATH] = { 0 };
    TCHAR ptDefaultLogPath[MAX_PATH] = { 0 };
    TCHAR atOutFileName[MAX_PATH] = { 0 };

    //
    // Init
    //
    //WPP_INIT_TRACING();
    LdapLibInit();
    CsvLibInit();
    JsonLibInit();
    UtilsLibInit();
    LogLibInit();

    bResult = UtilsHeapCreate(&g_pDirCrawlerHeap, DIR_CRAWLER_HEAP_NAME, NULL);
    if (!bResult) {
        FATAL(_T("Failed to create programm heap: <err:%#08x>"), UtilsGetLastError());
    }

    gs_pReqListHead = _aligned_malloc(sizeof(SLIST_HEADER), MEMORY_ALLOCATION_ALIGNMENT);
    if (gs_pReqListHead == NULL) {
        FATAL(_T("Failed to allocate request list header: <errno:%#08x>"), errno);
    }
    InitializeSListHead(gs_pReqListHead);

    gs_plSucceededRequestsCount = _aligned_malloc(sizeof(LONG), MEMORY_ALLOCATION_ALIGNMENT);
    if (gs_plSucceededRequestsCount == NULL) {
        FATAL(_T("Failed to allocate internal variable 'gs_plSucceededRequestsCount': <errno:%#08x>"), errno);
    }
    (*gs_plSucceededRequestsCount) = 0;

    //
    // Options parsing & verification
    //
    if (argc == 1) {
        DirCrawlerUsage(argv[0], NULL);
    }

    DirCrawlerParseOptions(&gs_sOptions, argc, argv);

    LOG(Succ, _T("Start"));

    if (gs_sOptions.ldap.ptLdapServer == NULL) {
        DirCrawlerUsage(argv[0], _T("Missing LDAP server"));
    }

    if (gs_sOptions.dump.ptOutputDir == NULL) {
        DirCrawlerUsage(argv[0], _T("Missing output directory"));
    }
    dwResult = GetFileAttributes(gs_sOptions.dump.ptOutputDir);
    if (dwResult == INVALID_FILE_ATTRIBUTES || (dwResult & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        FATAL(_T("Invalid output directory <%s>"), gs_sOptions.dump.ptOutputDir);
    }

    ptRootFolderName = DirCrawlerComputeOutputRootFolderName();
    if (!ptRootFolderName) {
       FATAL(_T("Unable to compute output directory architecture <%s>"), gs_sOptions.dump.ptOutputDir);
    }

    _stprintf_s(ptRootFolderPath, MAX_PATH, _T("%s\\%s"), gs_sOptions.dump.ptOutputDir, ptRootFolderName);
    if (DirCrawlerCreateFolderRecursively(ptRootFolderPath) != TRUE) {
       FATAL(_T("Unable to manually create directory architecture <%s>"), ptRootFolderPath);
    }

    _stprintf_s(ptDefaultResultsFolderPath, MAX_PATH, _T("%s\\%s\\Ldap"), gs_sOptions.dump.ptOutputDir, ptRootFolderName);
    if (DirCrawlerCreateFolderRecursively(ptDefaultResultsFolderPath) != TRUE) {
       FATAL(_T("Unable to manually create directory architecture <%s>"), ptDefaultResultsFolderPath);
    }

    _stprintf_s(ptDefaultLogPath, MAX_PATH, _T("%s\\%s\\Logs"), gs_sOptions.dump.ptOutputDir, ptRootFolderName);
    if (DirCrawlerCreateFolderRecursively(ptDefaultLogPath) != TRUE) {
       FATAL(_T("Unable to manually create directory architecture <%s>"), ptDefaultLogPath);
    }

    if (((gs_sOptions.ldap.ptLogin != NULL) ^ (gs_sOptions.ldap.ptPassword != NULL)) == TRUE) {
        DirCrawlerUsage(argv[0], _T("You must specify a username AND a password to use explicit authentication"));
    }

    LOG(Info, SUB_LOG(_T("LDAP server <%s:%u>")), gs_sOptions.ldap.ptLdapServer, gs_sOptions.ldap.dwLdapPort);
    if (gs_sOptions.ldap.ptLogin != NULL) {
        LOG(Info, SUB_LOG(_T("LDAP explicit authentication with username <%s%s%s>")),
            gs_sOptions.ldap.ptExplicitDomain != NULL ? gs_sOptions.ldap.ptExplicitDomain : EMPTY_STR,
            gs_sOptions.ldap.ptExplicitDomain ? _T("\\") : EMPTY_STR,
            gs_sOptions.ldap.ptLogin);
    }
    else {
        TCHAR atUserName[MAX_LINE] = { 0 };
        DWORD dwSize = MAX_LINE;
        GetUserName(atUserName, &dwSize);
        LOG(Info, SUB_LOG(_T("LDAP implicit authentication with username <%s>")), atUserName);
    }

    if (gs_sOptions.dump.ptJsonFile == NULL) {
        DirCrawlerUsage(argv[0], _T("Missing JSON request file"));
    }

    if (gs_sOptions.misc.dwMaxThreads > 1) {
        LOG(Info, SUB_LOG(_T("Using <%u> threads")), gs_sOptions.misc.dwMaxThreads);
        if (gs_sOptions.misc.dwMaxThreads >= MAXIMUM_WAIT_OBJECTS) {
            FATAL(_T("Cannot create more thread than 'MAXIMUM_WAIT_OBJECTS' <%u>"), MAXIMUM_WAIT_OBJECTS);
        }
        phThreads = UtilsHeapAllocArrayHelper(g_pDirCrawlerHeap, HANDLE, gs_sOptions.misc.dwMaxThreads);
        for (i = 0; i<gs_sOptions.misc.dwMaxThreads; i++){
            phThreads[i] = CreateThread(NULL, 0, DirCrawlerDoRequests, NULL, CREATE_SUSPENDED, NULL);
            if (phThreads[i] == NULL) {
                FATAL(_T("Failed to create thread <%u/%u>: <gle:%#08x>"), i + 1, gs_sOptions.misc.dwMaxThreads, GLE());
            }
            LOG(Dbg, SUB_LOG(SUB_LOG(_T("Thread <%u/%u>: <%#08x:%#08x>"))), i + 1, gs_sOptions.misc.dwMaxThreads, phThreads[i], GetThreadId(phThreads[i]));
        }
    }

    if (gs_sOptions.dump.requests.dwCount > 0) {
        LOG(Info, SUB_LOG(_T("Requests sublist:")));
        for (i = 0; i < gs_sOptions.dump.requests.dwCount; i++) {
            LOG(Info, SUB_LOG(SUB_LOG(_T("%s"))), gs_sOptions.dump.requests.pptList[i]);
        }
    }

    bResult = TRUE;
    bResult &= LogSetLogLevel(LogTypeConsole, gs_sOptions.log.ptLogLevelConsole);
    if (gs_sOptions.log.ptLogFile) {
       bResult &= LogSetLogFile(gs_sOptions.log.ptLogFile);
       bResult &= LogSetLogLevel(LogTypeLogfile, gs_sOptions.log.ptLogLevelFile);
    }
    if (bResult == FALSE) {
       FATAL(_T("Failed to setup log level and log file: <err:%#08x>"), LogGetLastError());
    }

    //
    // JSON Parsing
    //
    LOG(Succ, _T("Reading requests from JSON file <%s>"), gs_sOptions.dump.ptJsonFile);
    DirCrawlerJsonParseRequestFile(gs_sOptions.dump.ptJsonFile, &sRequestsDescriptions);
    LOG(Succ, SUB_LOG(_T("Read <%u> LDAP requests")), sRequestsDescriptions.dwRequestCount);

    //
    // LDAP connexion
    //
    LOG(Succ, _T("Connecting to LDAP server..."));
    bResult = LdapConnect(gs_sOptions.ldap.ptLdapServer, gs_sOptions.ldap.dwLdapPort, &pConnection, &gs_pRootDse);
    if (!bResult) {
        FATAL(_T("Failed to connect to LDAP server: <err:%#08x>"), LdapLastError());
    }

    for (i = 0; i < gs_pRootDse->computed.count.dwNamingContextsCount; i++) {
        LOG(Info, SUB_LOG(_T("NC: <%s>")), gs_pRootDse->extracted.pptNamingContexts[i]);
    }

    if (gs_sOptions.misc.ptOutfilesPrefix == NULL) {
        DirCrawlerSetDefaultPrefix(&gs_sOptions, gs_pRootDse);
        if (gs_sOptions.log.ptLogFile == NULL) {
           bResult = DirCrawlerFormatOutfile(atOutFileName, gs_sOptions.dump.ptOutputDir, DIR_CRAWLER_LOG_DIR, gs_sOptions.misc.ptOutfilesPrefix ? gs_sOptions.misc.ptOutfilesPrefix : DIR_CRAWLER_LOGFILE_PREFIX, DIR_CRAWLER_OUTFILES_KEYWORD, NULL, DIR_CRAWLER_LOGFILE_EXT);
           if (bResult == FALSE) {
              FATAL(_T("Failed to format outfile path"));
           }
           bResult &= LogSetLogFile(atOutFileName);
           if (bResult == FALSE) {
              FATAL(_T("Failed to setup log level and log file: <err:%#08x>"), LogGetLastError());
           }
        }
    }

    //
    // Dump
    //
    LOG(Succ, _T("Starting LDAP requests..."));
    for (i = sRequestsDescriptions.dwRequestCount - 1; i != (DWORD)-1; i--) {
        // Skip requests not present in the sublist if one has been specified
        if (gs_sOptions.dump.requests.dwCount > 0 && IsInSetOfStrings(sRequestsDescriptions.pRequestsDescriptions[i].infos.ptName, gs_sOptions.dump.requests.pptList, gs_sOptions.dump.requests.dwCount, NULL) == FALSE) {
            LOG(Warn, SUB_LOG(_T("Skipping <%s>")), sRequestsDescriptions.pRequestsDescriptions[i].infos.ptName);
        }
        // For all others requests: push them in the synchronized-linked-list
        else {
            pReqListEntry = _aligned_malloc(sizeof(DIR_CRAWLER_REQ_LIST_ENTRY), MEMORY_ALLOCATION_ALIGNMENT);
            if (pReqListEntry == NULL) {
                FATAL(_T("Failed to allocate request list entry: <errno:%#08x>"), errno);
            }
            pReqListEntry->pReqDescr = &sRequestsDescriptions.pRequestsDescriptions[i];
            InterlockedPushEntrySList(gs_pReqListHead, &pReqListEntry->sListEntry);
            dwSentReqCount += 1;
        }
    }
    // Then either start all the waiting worker threads, or call the 'DirCrawlerDoRequests' method manually if we're single-threaded
    if (gs_sOptions.misc.dwMaxThreads > 1) {
        // Multi-threaded
        for (i = 0; i < gs_sOptions.misc.dwMaxThreads; i++) {
            dwResult = ResumeThread(phThreads[i]);
            if (dwResult == (DWORD)-1) {
                FATAL(_T("Failed to resume worker-thread <%u/%u>: <gle:%#08x>"), i + 1, gs_sOptions.misc.dwMaxThreads, GLE());
            }
        }

        dwResult = WaitForMultipleObjects(gs_sOptions.misc.dwMaxThreads, phThreads, TRUE, INFINITE);
        if (dwResult != WAIT_OBJECT_0) {
            FATAL(_T("Failed to wait on all worker-threads: <%#08x>"), GLE());
        }
    }
    else {
        // Single-threaded
        DirCrawlerDoRequests(NULL);
    }

    LOG(Succ, _T("Done: <total:%u> <filtered:%u> <kept:%u> <succ:%u/%u> <fail:%u/%u> <time:%.3fs>"),
        sRequestsDescriptions.dwRequestCount,
        (sRequestsDescriptions.dwRequestCount - dwSentReqCount),
        dwSentReqCount,
        (*gs_plSucceededRequestsCount),
        dwSentReqCount,
        dwSentReqCount - (*gs_plSucceededRequestsCount),
        dwSentReqCount,
        TIME_DIFF_SEC(ullTimeStart, GetTickCount64()));

    if (dwSentReqCount - (*gs_plSucceededRequestsCount) == 0) {
        globalSuccess = TRUE;
    }
    //
    // Cleanup & exit
    //
    if (gs_sOptions.misc.dwMaxThreads > 1) {
        for (i = 0; i < gs_sOptions.misc.dwMaxThreads; i++) {
            CloseHandle(phThreads[i]);
            phThreads[i] = INVALID_HANDLE_VALUE;
        }
        UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, phThreads);
    }
    UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, gs_sOptions.dump.requests.pptList);
    UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, ptRootFolderName);
    DirCrawlerJsonReleaseRequests(&sRequestsDescriptions);
    LdapCloseConnection(&pConnection, &gs_pRootDse);
    UtilsHeapDestroy(&g_pDirCrawlerHeap);
    _aligned_free(gs_plSucceededRequestsCount);
    _aligned_free(gs_pReqListHead);

    LOG(Succ, _T("Exit."));

    //WPP_CLEANUP();
    LdapLibCleanup();
    CsvLibCleanup();
    JsonLibCleanup();
    UtilsLibCleanup();
    LogLibCleanup();

    if (globalSuccess) {
        return EXIT_SUCCESS;
    }
    else {
        return EXIT_FAILURE;
    }
}
