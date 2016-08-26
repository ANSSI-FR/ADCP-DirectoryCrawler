/* --- INCLUDES ------------------------------------------------------------- */
#include "DirCrawlerJson.h"

// TODO : améliorer les messages de logs de parsing du fichier JSON et ajouter des logs Info pour les différentes requetes

/* --- PRIVATE VARIABLES ---------------------------------------------------- */
/* --- PUBLIC VARIABLES ----------------------------------------------------- */
/* --- PRIVATE FUNCTIONS ---------------------------------------------------- */
static BOOL DirCrawlerEntryExtractLdapSingleCtrlOidStr(
    _In_ const PJSON_OBJECT pJsonElement,   // type str, OID of an ldap control of a request, ("oid": "...")
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_LDAP_CONTROL_DESCRIPTION
    ) {
    ((PDIR_CRAWLER_LDAP_CONTROL_DESCRIPTION)pvContext)->ptOid = UtilsHeapStrDupHelper(g_pDirCrawlerHeap, JSON_STRVAL(pJsonElement));
    return TRUE;
}

static BOOL DirCrawlerEntryExtractLdapSingleCtrlValueStr(
    _In_ const PJSON_OBJECT pJsonElement,   // type str, value of an ldap control of a request, ("value": "...")
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_LDAP_CONTROL_DESCRIPTION
    ) {
    PDIR_CRAWLER_LDAP_CONTROL_DESCRIPTION pCtrlDescr = pvContext;

    if (pCtrlDescr->bHasValue == FALSE) {
        FATAL(_T("JSON error: control value <%s> specified without a type ('valuetype' must preceed 'value')"), JSON_STRVAL(pJsonElement));
    }

    switch (pCtrlDescr->eValueType) {
    case DirCrawlerTypeStr:
        pCtrlDescr->value.ptVal = UtilsHeapStrDupHelper(g_pDirCrawlerHeap, JSON_STRVAL(pJsonElement));
        break;
    case DirCrawlerTypeInt:
        if (IsNumeric(JSON_STRVAL(pJsonElement)) == FALSE) {
            FATAL(_T("JSON error: value <%s> of type 'int' is not numeric"), JSON_STRVAL(pJsonElement));
        }
        pCtrlDescr->value.iVal = _tstoi(JSON_STRVAL(pJsonElement));
        break;
    case DirCrawlerTypeBin:
        pCtrlDescr->value.bin.dwLen = (DWORD)_tcslen(JSON_STRVAL(pJsonElement))/2;
        pCtrlDescr->value.bin.pvVal = UtilsHeapAllocHelper(g_pDirCrawlerHeap, pCtrlDescr->value.bin.dwLen);
        Unhexify(pCtrlDescr->value.bin.pvVal, JSON_STRVAL(pJsonElement));
        break;
    }

    return TRUE;
}

static BOOL DirCrawlerEntryExtractLdapSingleCtrlValueTypeStr(
    _In_ const PJSON_OBJECT pJsonElement,   // type str, value-type of an ldap control of a request, ("valuetype": "...")
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_LDAP_CONTROL_DESCRIPTION
    ) {
    static const PTCHAR sc_aptCtrlValTypes[] = { JSON_TYPE_STR, JSON_TYPE_INT, JSON_TYPE_BIN };
    static const LDAP_REQ_SCOPE sc_aeCtrlValTypes[] = { DirCrawlerTypeStr, DirCrawlerTypeInt, DirCrawlerTypeBin };
    static_assert(_countof(sc_aptCtrlValTypes) == _countof(sc_aeCtrlValTypes), "Invalid array count");
    PDIR_CRAWLER_LDAP_CONTROL_DESCRIPTION pCtrlDescr = pvContext;
    DWORD dwIndex = 0;

    if (STR_EQ(JSON_TYPE_NONE, JSON_STRVAL(pJsonElement))){
        pCtrlDescr->bHasValue = FALSE;
    }
    else if (IsInSetOfStrings(JSON_STRVAL(pJsonElement), sc_aptCtrlValTypes, _countof(sc_aptCtrlValTypes), &dwIndex)) {
        pCtrlDescr->bHasValue = TRUE;
        pCtrlDescr->eValueType = sc_aeCtrlValTypes[dwIndex];
    }
    else {
        FATAL(_T("JSON error: invalid control value-type <%s>"), JSON_STRVAL(pJsonElement));
    }

    return TRUE;
}

static BOOL DirCrawlerEntryExtractLdapSingleCtrlCtrlTypeStr(
    _In_ const PJSON_OBJECT pJsonElement,   // type str, control-type of an ldap control of a request, ("ctrltype": "client|server")
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_LDAP_CONTROL_DESCRIPTION
    ) {
    static const PTCHAR sc_aptCtrlCtrlTypes[] = { JSON_CONTROL_TYPE_CLIENT, JSON_CONTROL_TYPE_SERVER };
    static const LDAP_REQ_SCOPE sc_aeCtrlCtrlTypes[] = { DirCrawlerLdapCtrlClient, DirCrawlerLdapCtrlServer };
    static_assert(_countof(sc_aptCtrlCtrlTypes) == _countof(sc_aeCtrlCtrlTypes), "Invalid array count");

    DWORD dwIndex = 0;

    if (IsInSetOfStrings(JSON_STRVAL(pJsonElement), sc_aptCtrlCtrlTypes, _countof(sc_aptCtrlCtrlTypes), &dwIndex)) {
        ((PDIR_CRAWLER_LDAP_CONTROL_DESCRIPTION)pvContext)->eCtrlType = sc_aeCtrlCtrlTypes[dwIndex];
    }
    else {
        FATAL(_T("JSON error: invalid control control-type <%s>"), JSON_STRVAL(pJsonElement));
    }

    return TRUE;
}

static BOOL DirCrawlerEntryExtractLdapSingleCtrlNameStr(
    _In_ const PJSON_OBJECT pJsonElement,   // type str, name of an ldap control of a request, ("name": "...")
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_LDAP_CONTROL_DESCRIPTION
    ) {
    ((PDIR_CRAWLER_LDAP_CONTROL_DESCRIPTION)pvContext)->ptName = UtilsHeapStrDupHelper(g_pDirCrawlerHeap, JSON_STRVAL(pJsonElement));
    return TRUE;
}

static BOOL DirCrawlerEntryExtractLdapSingleCtrl(
    _In_ const PJSON_OBJECT pJsonElement,   // type ? must be obj, represents an ldap control of a request, ({"type":..., "ctrltype":..., "valuetype":..., "value":..., "oid":...})
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_REQ_DESCR
    ) {
    static const JSON_REQUESTED_ELEMENT sc_asJsonLdapCrtlElements[] = {
        { .ptKey = JSON_TOKEN_NAME, .eExpectedType = JsonResultTypeString, .pfnCallback = DirCrawlerEntryExtractLdapSingleCtrlNameStr, .bMustBePresent = TRUE },
        { .ptKey = JSON_TOKEN_CONTROL_TYPE, .eExpectedType = JsonResultTypeString, .pfnCallback = DirCrawlerEntryExtractLdapSingleCtrlCtrlTypeStr, .bMustBePresent = TRUE },
        { .ptKey = JSON_TOKEN_VALUE_TYPE, .eExpectedType = JsonResultTypeString, .pfnCallback = DirCrawlerEntryExtractLdapSingleCtrlValueTypeStr, .bMustBePresent = TRUE },
        { .ptKey = JSON_TOKEN_VALUE, .eExpectedType = JsonResultTypeString, .pfnCallback = DirCrawlerEntryExtractLdapSingleCtrlValueStr, .bMustBePresent = FALSE },
        { .ptKey = JSON_TOKEN_OID, .eExpectedType = JsonResultTypeString, .pfnCallback = DirCrawlerEntryExtractLdapSingleCtrlOidStr, .bMustBePresent = TRUE },
    };
    PDIR_CRAWLER_REQ_DESCR pReqDescr = pvContext;

    if (pJsonElement->eObjectType != JsonResultTypeObject) {
        FATAL(_T("JSON error: control <%u> of sub-element <%s> is not an object"), pReqDescr->ldap.controls.dwCtrlCount, pReqDescr->infos.ptName);
    }

    pReqDescr->ldap.controls.pCtrlArray = UtilsHeapAllocOrReallocHelper(g_pDirCrawlerHeap, pReqDescr->ldap.controls.pCtrlArray, SIZEOF_ARRAY(DIR_CRAWLER_LDAP_CONTROL_DESCRIPTION, pReqDescr->ldap.controls.dwCtrlCount + 1));
    return JsonObjectForeachRequestedElement(pJsonElement, FALSE, sc_asJsonLdapCrtlElements, _countof(sc_asJsonLdapCrtlElements), &pReqDescr->ldap.controls.pCtrlArray[pReqDescr->ldap.controls.dwCtrlCount], NULL);
}

static BOOL DirCrawlerEntryExtractLdapCtrlsArr(
    _In_ const PJSON_OBJECT pJsonElement,   // type arr, contains objects representing ldap controls of a request, ([{...}, {...}, ...])
    _In_ const PVOID pvContext              // never null, type DIR_CRAWLER_REQ_DESCR
    ) {
    PDIR_CRAWLER_REQ_DESCR pReqDescr = (PDIR_CRAWLER_REQ_DESCR)pvContext;
    BOOL bResult = JsonForeachElement(pJsonElement, DirCrawlerEntryExtractLdapSingleCtrl, pvContext, &pReqDescr->ldap.controls.dwCtrlCount);
    if (bResult == FALSE) {
        FATAL(_T("JSON error while parsing controls for sub-element <%s>"), pReqDescr->infos.ptName);
    }
    LOG(Info, SUB_LOG(SUB_LOG(_T("Ctrl count: <%u>"))), pReqDescr->ldap.eScope, pReqDescr->ldap.controls.dwCtrlCount);
    return bResult;
}

static BOOL DirCrawlerEntryExtractLdapSingleAttrTypeStr(
    _In_ const PJSON_OBJECT pJsonElement,   // type str, type of an ldap attribute of a request, ("type": "str|int|bin")
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION
    ) {
    static const PTCHAR sc_aptAttrTypes[] = { JSON_TYPE_STR, JSON_TYPE_INT, JSON_TYPE_BIN };
    static const LDAP_REQ_SCOPE sc_aeAttrTypes[] = { DirCrawlerTypeStr, DirCrawlerTypeInt, DirCrawlerTypeBin };
    static_assert(_countof(sc_aptAttrTypes) == _countof(sc_aeAttrTypes), "Invalid array count");

    DWORD dwIndex = 0;

    if (IsInSetOfStrings(JSON_STRVAL(pJsonElement), sc_aptAttrTypes, _countof(sc_aptAttrTypes), &dwIndex)) {
        ((PDIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION)pvContext)->eType = sc_aeAttrTypes[dwIndex];
    }
    else {
        FATAL(_T("JSON error: invalid attribute type <%s>"),  JSON_STRVAL(pJsonElement));
    }

    return TRUE;
}

static BOOL DirCrawlerEntryExtractLdapSingleAttrNameStr(
    _In_ const PJSON_OBJECT pJsonElement,   // type str, name of an ldap attribute of a request, ("name": "...")
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION
    ) {
    ((PDIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION)pvContext)->ptName = UtilsHeapStrDupHelper(g_pDirCrawlerHeap, JSON_STRVAL(pJsonElement));
    return TRUE;
}

static BOOL DirCrawlerEntryExtractLdapSingleAttr(
    _In_ const PJSON_OBJECT pJsonElement,   // type ? must be obj, represents an ldap attribute of a request, ({"type":..., "name":...})
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_REQ_DESCR
    ) {
    static const JSON_REQUESTED_ELEMENT sc_asJsonLdapAttrElements[] = {
        { .ptKey = JSON_TOKEN_TYPE, .eExpectedType = JsonResultTypeString, .pfnCallback = DirCrawlerEntryExtractLdapSingleAttrTypeStr, .bMustBePresent = TRUE },
        { .ptKey = JSON_TOKEN_NAME, .eExpectedType = JsonResultTypeString, .pfnCallback = DirCrawlerEntryExtractLdapSingleAttrNameStr, .bMustBePresent = TRUE },
    };
    PDIR_CRAWLER_REQ_DESCR pReqDescr = pvContext;

    if (pJsonElement->eObjectType != JsonResultTypeObject) {
        FATAL(_T("JSON error: attribute <%u> of sub-element <%s> is not an object"), pReqDescr->ldap.attributes.dwAttrCount, pReqDescr->infos.ptName);
    }
    
    pReqDescr->ldap.attributes.pAttrArray = UtilsHeapAllocOrReallocHelper(g_pDirCrawlerHeap, pReqDescr->ldap.attributes.pAttrArray, SIZEOF_ARRAY(DIR_CRAWLER_LDAP_ATTRIBUTE_DESCRIPTION, pReqDescr->ldap.attributes.dwAttrCount + 1));
    return JsonObjectForeachRequestedElement(pJsonElement, FALSE, sc_asJsonLdapAttrElements, _countof(sc_asJsonLdapAttrElements), &pReqDescr->ldap.attributes.pAttrArray[pReqDescr->ldap.attributes.dwAttrCount], NULL);
}

static BOOL DirCrawlerEntryExtractLdapAttrsArr(
    _In_ const PJSON_OBJECT pJsonElement,   // type arr, contains objects representing ldap attributes of a request, ([{...}, {...}, ...])
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_REQ_DESCR
    ) {
    PDIR_CRAWLER_REQ_DESCR pReqDescr = (PDIR_CRAWLER_REQ_DESCR)pvContext;
    BOOL bResult = JsonForeachElement(pJsonElement, DirCrawlerEntryExtractLdapSingleAttr, pvContext, &pReqDescr->ldap.attributes.dwAttrCount);
    if (bResult == FALSE) {
        FATAL(_T("JSON error while parsing attributes for sub-element <%s>"), pReqDescr->infos.ptName);
    }
    LOG(Info, SUB_LOG(SUB_LOG(_T("Attr count: <%u>"))), pReqDescr->ldap.attributes.dwAttrCount);
    return bResult;
}

static BOOL DirCrawlerEntryExtractLdapBaseStr(
    _In_ const PJSON_OBJECT pJsonElement,   // type str, ldap base of a request, ("base": "domain|configuration|schema|domainDns|forestDns|*|...")
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_REQ_DESCR
    ) {
    static const PTCHAR sc_aptWellKnownBases[] = { JSON_BASE_WELLKNOW_NC_DOMAIN, JSON_BASE_WELLKNOW_NC_CONFIG, JSON_BASE_WELLKNOW_NC_SCHEMA, JSON_BASE_WELLKNOW_NC_DOMDNS, JSON_BASE_WELLKNOW_NC_FORDNS };
    static const LDAP_REQ_SCOPE sc_aeWellKnownBases[] = { DirCrawlerLdapNcDomain, DirCrawlerLdapNcConfiguration, DirCrawlerLdapNcSchema, DirCrawlerLdapNcDomainDnsZones, DirCrawlerLdapNcForestDnsZones };
    static_assert(_countof(sc_aptWellKnownBases) == _countof(sc_aeWellKnownBases), "Invalid array count");
    PDIR_CRAWLER_REQ_DESCR pReqDescr = (PDIR_CRAWLER_REQ_DESCR)pvContext;
    DWORD dwIndex = 0;
    
    if (STR_EQ(JSON_BASE_WILDCARD_NC, JSON_STRVAL(pJsonElement))) {
        pReqDescr->ldap.base.eType = DirCrawlerLdapBaseWildcardAll;
        LOG(Info, SUB_LOG(SUB_LOG(_T("Base      : <*>"))));
    }
    else if (IsInSetOfStrings(JSON_STRVAL(pJsonElement), sc_aptWellKnownBases, _countof(sc_aptWellKnownBases), &dwIndex)){
        pReqDescr->ldap.base.eType = DirCrawlerLdapBaseNcShortcut;
        pReqDescr->ldap.base.value.eBaseNcShortcut = sc_aeWellKnownBases[dwIndex];
        LOG(Info, SUB_LOG(SUB_LOG(_T("Base      : <%u:%s>"))), pReqDescr->ldap.base.value.eBaseNcShortcut, JSON_STRVAL(pJsonElement));
    }
    else {
        pReqDescr->ldap.base.eType = DirCrawlerLdapBaseDN;
        pReqDescr->ldap.base.value.ptBaseDN = UtilsHeapStrDupHelper(g_pDirCrawlerHeap, JSON_STRVAL(pJsonElement));
        LOG(Info, SUB_LOG(SUB_LOG(_T("Base      : <%s>"))), pReqDescr->ldap.base.value.ptBaseDN);
    }

    return TRUE;
}

static BOOL DirCrawlerEntryExtractLdapScopeStr(
    _In_ const PJSON_OBJECT pJsonElement,   // type str, ldap scope of a request, ("scope": "base|onelevel|subtree")
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_REQ_DESCR
    ) {
    static const PTCHAR sc_aptScopes[] = { JSON_SCOPE_BASE, JSON_SCOPE_ONELEVEL, JSON_SCOPE_SUBTREE };
    static const LDAP_REQ_SCOPE sc_aeScopes[] = { LdapScopeBase, LdapScopeOneLevel, LdapScopeSubtree };
    static_assert(_countof(sc_aptScopes) == _countof(sc_aeScopes), "Invalid array count");
    PDIR_CRAWLER_REQ_DESCR pReqDescr = pvContext;
    DWORD dwIndex = 0;

    if (IsInSetOfStrings(JSON_STRVAL(pJsonElement), sc_aptScopes, _countof(sc_aptScopes), &dwIndex)) {
        pReqDescr->ldap.eScope = sc_aeScopes[dwIndex];
        LOG(Info, SUB_LOG(SUB_LOG(_T("Scope     : <%u:%s>"))), pReqDescr->ldap.eScope, JSON_STRVAL(pJsonElement));
    }
    else {
        FATAL(_T("JSON error for sub-element <%s>: invalide scope <%s>"), pReqDescr->infos.ptName, JSON_STRVAL(pJsonElement));
    }

    return TRUE;
}

static BOOL DirCrawlerEntryExtractLdapFilterStr(
    _In_ const PJSON_OBJECT pJsonElement,   // type str, ldap filter of a request, ("filter": "...")
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_REQ_DESCR
    ) {
    PDIR_CRAWLER_REQ_DESCR pReqDescr = pvContext;
    pReqDescr->ldap.ptFilter = UtilsHeapStrDupHelper(g_pDirCrawlerHeap, JSON_STRVAL(pJsonElement));
    LOG(Info, SUB_LOG(SUB_LOG(_T("Filter    : <%s>"))), pReqDescr->ldap.ptFilter);
    return TRUE;
}

static BOOL DirCrawlerEntryExtractLdapObj(
    _In_ const PJSON_OBJECT pJsonElement,   // type obj, contains ldap attributes, ("ldap": {"base":..., "scope":..., "filter":..., "attrs":..., "ctrls":...)
    _In_opt_ const PVOID pvContext          // never null, type PDIR_CRAWLER_REQ_DESCR
    ) {
    static const JSON_REQUESTED_ELEMENT sc_asJsonLdapElements[] = {
        { .ptKey = JSON_TOKEN_BASE, .eExpectedType = JsonResultTypeString, .pfnCallback = DirCrawlerEntryExtractLdapBaseStr, .bMustBePresent = TRUE },
        { .ptKey = JSON_TOKEN_SCOPE, .eExpectedType = JsonResultTypeString, .pfnCallback = DirCrawlerEntryExtractLdapScopeStr, .bMustBePresent = TRUE },
        { .ptKey = JSON_TOKEN_FILTER, .eExpectedType = JsonResultTypeString, .pfnCallback = DirCrawlerEntryExtractLdapFilterStr, .bMustBePresent = TRUE },
        { .ptKey = JSON_TOKEN_ATTRS, .eExpectedType = JsonResultTypeArray, .pfnCallback = DirCrawlerEntryExtractLdapAttrsArr, .bMustBePresent = TRUE },
        { .ptKey = JSON_TOKEN_CONTROLS, .eExpectedType = JsonResultTypeArray, .pfnCallback = DirCrawlerEntryExtractLdapCtrlsArr, .bMustBePresent = FALSE },
    };
    return JsonObjectForeachRequestedElement(pJsonElement, FALSE, sc_asJsonLdapElements, _countof(sc_asJsonLdapElements), pvContext, NULL);
}

static BOOL DirCrawlerEntryExtractDescrStr(
    _In_ const PJSON_OBJECT pJsonElement,   // type str, descr of a request, ("descr": "...")
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_REQ_DESCR
    ) {
    PDIR_CRAWLER_REQ_DESCR pReqDescr = pvContext;
    pReqDescr->infos.ptDescription = UtilsHeapStrDupHelper(g_pDirCrawlerHeap, JSON_STRVAL(pJsonElement));
    LOG(Info, SUB_LOG(SUB_LOG(_T("Descr     : <%s>"))), pReqDescr->infos.ptDescription);
    return TRUE;
}

static BOOL DirCrawlerEntryExtractRequest(
    _In_ const PJSON_OBJECT pJsonElement,   // must have type str, describes a request, ("name": {"descr":..., "ldap":...} )
    _In_ const PVOID pvContext              // never null, type PDIR_CRAWLER_REQ_DESCR_ARRAY
    ) {
    static const JSON_REQUESTED_ELEMENT sc_asJsonMainElements[] = {
        { .ptKey = JSON_TOKEN_DESCR, .eExpectedType = JsonResultTypeString, .pfnCallback = DirCrawlerEntryExtractDescrStr, .bMustBePresent = TRUE },
        { .ptKey = JSON_TOKEN_LDAP, .eExpectedType = JsonResultTypeObject, .pfnCallback = DirCrawlerEntryExtractLdapObj, .bMustBePresent = TRUE },
    };
    BOOL bResult = FALSE;
    PDIR_CRAWLER_REQ_DESCR_ARRAY pReqDescr = pvContext;

    if (pJsonElement->eObjectType != JsonResultTypeObject) {
        FATAL(_T("JSON error: sub-element <%s> is not an object"), pJsonElement->ptKey);
    }

    pReqDescr->pRequestsDescriptions = UtilsHeapAllocOrReallocHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions, SIZEOF_ARRAY(DIR_CRAWLER_REQ_DESCR, pReqDescr->dwRequestCount + 1));
    pReqDescr->pRequestsDescriptions[pReqDescr->dwRequestCount].infos.ptName = UtilsHeapStrDupHelper(g_pDirCrawlerHeap, pJsonElement->ptKey);
    LOG(Info, SUB_LOG(_T("Request <%u:%s>")), pReqDescr->dwRequestCount, pJsonElement->ptKey);

    bResult = JsonObjectForeachRequestedElement(pJsonElement, FALSE, sc_asJsonMainElements, _countof(sc_asJsonMainElements), &(pReqDescr->pRequestsDescriptions[pReqDescr->dwRequestCount]), NULL);
    if (API_FAILED(bResult)) {
        FATAL(_T("JSON error for sub-element <%s>: <err:%#08x>"), pJsonElement->ptKey, JsonGetLastError());
    }

    return TRUE;
}

/* --- PUBLIC FUNCTIONS ----------------------------------------------------- */
void DirCrawlerJsonParseRequestFile(
    _In_ const PTCHAR ptJsonFile,
    _In_ const PDIR_CRAWLER_REQ_DESCR_ARRAY pReqDescr
    ) {
    BOOL bResult = FALSE;
    PJSON_OBJECT pJsonRoot = NULL;

    pReqDescr->pRequestsDescriptions = NULL;
    pReqDescr->dwRequestCount = 0;

    bResult = JsonOpenFileRead(ptJsonFile, &pJsonRoot);
    if (API_FAILED(bResult)) {
        FATAL(_T("JSON error: cannot open file <err:%#08x>"), JsonGetLastError());
    }

    if (pJsonRoot->eObjectType != JsonResultTypeObject) {
        FATAL(_T("JSON error: root element is not an object"));
    }

    bResult = JsonForeachElement(pJsonRoot, DirCrawlerEntryExtractRequest, pReqDescr, &pReqDescr->dwRequestCount);
    if (API_FAILED(bResult)) {
        FATAL(_T("JSON error: requests parsing error <err:%#08x>"), JsonGetLastError());
    }

    JsonReleaseObject(&pJsonRoot);
}

void DirCrawlerJsonReleaseRequests(
    _In_ const PDIR_CRAWLER_REQ_DESCR_ARRAY pReqDescr
    ) {
    DWORD i = 0, j = 0;

    for (i = 0; i < pReqDescr->dwRequestCount; i++) {
        UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions[i].ldap.ptFilter);
        UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions[i].infos.ptDescription);
        UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions[i].infos.ptName);

        if (pReqDescr->pRequestsDescriptions[i].ldap.base.eType == DirCrawlerLdapBaseDN) {
            UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions[i].ldap.base.value.ptBaseDN);
        }

        for (j = 0; j < pReqDescr->pRequestsDescriptions[i].ldap.attributes.dwAttrCount; j++) {
            UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions[i].ldap.attributes.pAttrArray[j].ptName);
        }
        UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions[i].ldap.attributes.pAttrArray);
        pReqDescr->pRequestsDescriptions[i].ldap.attributes.dwAttrCount = 0;

        for (j = 0; j < pReqDescr->pRequestsDescriptions[i].ldap.controls.dwCtrlCount; j++) {
            UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions[i].ldap.controls.pCtrlArray[j].ptName);
            UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions[i].ldap.controls.pCtrlArray[j].ptOid);
            if (pReqDescr->pRequestsDescriptions[i].ldap.controls.pCtrlArray[j].bHasValue == TRUE) {
                switch (pReqDescr->pRequestsDescriptions[i].ldap.controls.pCtrlArray[j].eValueType) {
                case DirCrawlerTypeStr:
                    UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions[i].ldap.controls.pCtrlArray[j].value.ptVal);
                    break;
                case DirCrawlerTypeBin:
                    UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions[i].ldap.controls.pCtrlArray[j].value.bin.pvVal);
                    break;
                }
            }
        }
        UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions[i].ldap.controls.pCtrlArray);
        pReqDescr->pRequestsDescriptions[i].ldap.controls.dwCtrlCount = 0;
    }

    UtilsHeapFreeAndNullHelper(g_pDirCrawlerHeap, pReqDescr->pRequestsDescriptions);
    pReqDescr->dwRequestCount = 0;
}
