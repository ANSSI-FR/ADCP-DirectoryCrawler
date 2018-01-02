#ifndef __DIR_CRAWLER_FORMATTERS_H__
#define __DIR_CRAWLER_FORMATTERS_H__

/* --- INCLUDES ------------------------------------------------------------- */
#include "DirectoryCrawler.h"

/* --- DEFINES -------------------------------------------------------------- */
/* --- TYPES ---------------------------------------------------------------- */
// Data formaters
//  - if pOutBuff == return the len only
//  - the len is in 'characters' not bytes
//  - the len includes a null terminator
typedef DWORD(FN_LDAP_ATTR_VALUE_FORMATTER)(
    _In_ PLDAP_VALUE pLdapValue,
    _In_opt_ LPSTR ptOutBuff
    );
typedef FN_LDAP_ATTR_VALUE_FORMATTER *PFN_LDAP_ATTR_VALUE_FORMATTER;

/* --- VARIABLES ------------------------------------------------------------ */
extern const PFN_LDAP_ATTR_VALUE_FORMATTER gc_ppfnFormatters[];

/* --- PROTOTYPES ----------------------------------------------------------- */
FN_LDAP_ATTR_VALUE_FORMATTER FormatLdapAttrStr;
FN_LDAP_ATTR_VALUE_FORMATTER FormatLdapAttrInt;
FN_LDAP_ATTR_VALUE_FORMATTER FormatLdapAttrBin;

#endif // __DIR_CRAWLER_FORMATTERS_H__
