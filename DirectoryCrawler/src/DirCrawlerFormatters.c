/* --- INCLUDES ------------------------------------------------------------- */
#include "DirCrawlerFormatters.h"

/* --- PRIVATE VARIABLES ---------------------------------------------------- */
/* --- PUBLIC VARIABLES ----------------------------------------------------- */
const PFN_LDAP_ATTR_VALUE_FORMATTER gc_ppfnFormatters[] = {
    [DirCrawlerTypeStr] = FormatLdapAttrStr,
    [DirCrawlerTypeInt] = FormatLdapAttrInt,
    [DirCrawlerTypeBin] = FormatLdapAttrBin,
};

/* --- PRIVATE FUNCTIONS ---------------------------------------------------- */
/* --- PUBLIC FUNCTIONS ----------------------------------------------------- */
DWORD FormatLdapAttrStr(
    _In_ PLDAP_VALUE pLdapValue,
    _In_opt_ LPSTR ptOutBuff
    ) {
    DWORD i = 0;
    DWORD dwEscaped = 0;
    LPSTR pStr = (LPSTR)pLdapValue->pbData;

    if (ptOutBuff == NULL) {
        for (i = 0; pStr[i] != _T('\0'); i++) {
            if (pStr[i] == DIR_CRAWLER_LDAP_VAL_SEPARATOR) {
                dwEscaped += 1;
            }
        }
    }
    else {
        for (i = 0; pStr[i] != _T('\0'); i++) {
            if (pStr[i] == DIR_CRAWLER_LDAP_VAL_SEPARATOR) {
                ptOutBuff[i + dwEscaped] = DIR_CRAWLER_SEPARATOR_ESCAPE;
                dwEscaped += 1;
            }
            ptOutBuff[i + dwEscaped] = pStr[i];
        }
        ptOutBuff[i + dwEscaped] = _T('\0');
    }

    return (i + dwEscaped + 1);
}

DWORD FormatLdapAttrInt(
    _In_ PLDAP_VALUE pLdapValue,
    _In_opt_ LPSTR ptOutBuff
    ) {
    // Numeric values are actually received as strings from the LDAP server
    // We just verify here that the value is *actually* numeric
    if (IsNumericA((PCHAR)pLdapValue->pbData)) {
        return FormatLdapAttrStr(pLdapValue, ptOutBuff);
    }
    else {
#ifdef _DEBUG
        DebugBreak();
#endif
        LOG(Warn, _T("Non-numeric value when exepecting one: <len:%u> <ptr:%p> <val:%*s>"), pLdapValue->dwSize, pLdapValue->pbData, pLdapValue->dwSize, pLdapValue->pbData);
        if (ptOutBuff != NULL) {
            ptOutBuff[0] = '\0';
        }
        return 1;
    }
}

DWORD FormatLdapAttrBin(
    _In_ PLDAP_VALUE pLdapValue,
    _In_opt_ LPSTR ptOutBuff
    ) {
    DWORD dwLen = (pLdapValue->dwSize * 2) + 1;

    if (ptOutBuff != NULL) {
        HexifyA(ptOutBuff, pLdapValue->pbData, pLdapValue->dwSize);
    }

    return dwLen;
}
