#include "includes.h"


DWORD
VMCARESTVerifyOAuth(
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse
    )
{
    DWORD dwError           = 0;
    PSTR pszAuthorization   = NULL;
    PSTR pszBearer          = NULL;
    PSTR pszToken           = NULL;

    dwError = VmRESTGetHttpHeader(
                pRequest,
                "Authorization",
                &pszAuthorization
                );
    BAIL_ON_VMREST_ERROR(dwError);

    if ( IsNullOrEmptyString(pszAuthorization) )
    {
        dwError = EACCES;
        BAIL_ON_VMREST_ERROR(dwError);
    }

    pszBearer = strstr(pszAuthorization, "Bearer ");
    if ( IsNullOrEmptyString(pszBearer) )
    {
        dwError = EACCES;
        BAIL_ON_VMREST_ERROR(dwError);
    }

    pszToken = pszBearer + strlen("Bearer ");
 

cleanup:
    return dwError;

error:
    goto cleanup;
}
