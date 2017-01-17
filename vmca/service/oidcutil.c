/*
 * Copyright © 2012-2016 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the ~@~\License~@~]); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ~@~\AS IS~@~] BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include "includes.h"


static
DWORD
VMCAGetTenantSigningCert(
    PSTR* ppszSigningCertPEM
    );

DWORD
VMCAVerifyOIDC(
    PVMCA_AUTHORIZATION_PARAM pAuthorization,
    PVMCA_ACCESS_TOKEN* ppAccessToken
    )
{
    DWORD dwError = 0;
    PVMCA_ACCESS_TOKEN pAccessToken = NULL;
    PSTR pszTenantSigningCert = NULL;
    POIDC_ACCESS_TOKEN pOIDCToken = NULL;

    if (!pAuthorization || !ppAccessToken)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    dwError = VMCAGetTenantSigningCert(&pszTenantSigningCert);
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = OidcClientGlobalInit();
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = OidcAccessTokenBuild(
                  &pOIDCToken,
                  pAuthorization->pAuthorization,
                  pszTenantSigningCert,
                  NULL,
                  VMCA_DEFAULT_CLOCK_TOLERANCE
                  );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAAllocateMemory(
                        sizeof(VMCA_ACCESS_TOKEN),
                        (PVOID*)&pAccessToken
                        );
    BAIL_ON_VMCA_ERROR(dwError);

    pAccessToken->tokenType = pAuthorization->tokenType;

    pAccessToken->pszSubjectName = OidcIDTokenGetSubject(pOIDCToken);

    if (pAccessToken->pszSubjectName == NULL)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    OidcIDTokenGetGroups(
                  pOIDCToken,
                  &pAccessToken->pszGroups,
                  &pAccessToken->dwGroupSize
                  );

    if (pAccessToken->pszGroups == NULL)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    pAccessToken->pOidcToken = pOIDCToken;
    pOIDCToken = NULL;

    *ppAccessToken = pAccessToken;

cleanup:
    VMCA_SAFE_FREE_STRINGA(pszTenantSigningCert);
    if (pOIDCToken)
    {
      //TODO: Find FREE function for pOIDCToken
    }
    return dwError;

error:
    if (ppAccessToken)
    {
        *ppAccessToken = NULL;
    }
    if (pAccessToken)
    {
        VMCAFreeAccessToken(pAccessToken);
    }
    goto cleanup;
}

VOID
VMCAFreeOIDC(
    PVMCA_ACCESS_TOKEN pAccessToken
    )
{
    if (pAccessToken)
    {
        if (pAccessToken->pOidcToken)
        {
            //FIND function to freeOIDC token
        }
    }
}

static
DWORD
VMCAGetTenantSigningCert(
    PSTR* ppszSigningCertPEM
    )
{
    DWORD dwError = 0;
    PSTR pszSigningCertPEM = NULL;
    PSTR pszDomainName = NULL;

    if (!ppszSigningCertPEM)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    dwError = VmAfdGetDomainNameA(NULL, &pszDomainName);
    BAIL_ON_VMCA_ERROR(dwError);

    //Get signing certificate from Directory
    //
    *ppszSigningCertPEM = pszSigningCertPEM;

cleanup:
    VMCA_SAFE_FREE_MEMORY(pszDomainName);
    return dwError;

error:
    if (ppszSigningCertPEM)
    {
        *ppszSigningCertPEM = NULL;
    }
    VMCA_SAFE_FREE_MEMORY(pszSigningCertPEM);
    goto cleanup;
}
