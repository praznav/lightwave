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
VMCAGetAccessTokenFromParameter(
    PSTR pszAccessTokenParameter,
    PVMCA_OIDC_ACCESS_TOKEN* ppAccessToken
    );

static
DWORD
VMCAGetTenantSigningCert(
    PSTR* ppszSigningCertPEM
    );

DWORD
VMCAAuthenticateOIDC(
    pRESTRequest pRESTRequest,
    PVMCA_OIDC_ACCESS_TOKEN_DETAILS *ppToken
    )
{
    DWORD dwError = 0;
    PSTR pszTenantSigningCert = NULL;
    PSTR pszAccessTokenParameter = NULL;
    PVMCA_OIDC_ACCESS_TOKEN pAccessToken = NULL;
    PVMCA_OIDC_ACCESS_TOKEN_DETAILS pToken = NULL;
    POIDC_ACCESS_TOKEN pOIDCToken = NULL;

    //Get Token from the header
    //Pass it to OIDC to verify if signed by the right certificate
    //Get type of token
    //if bearer token - Get group and return
    //If Holder of Key - Verify if the URL is signed by the public key


    if (!pRESTRequest || !ppToken)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    dwError = VmRESTGetHttpHeader(
                        pRESTRequest,
                        "Authorization",
                        &pszAccessTokenParameter
                        );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAGetAccessTokenFromParameter(
                                        pszAccessTokenParameter,
                                        &pAccessToken
                                        );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAGetTenantSigningCert(&pszTenantSigningCert);
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = OidcClientGlobalInit();
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = OidcAccessTokenBuild(
                  &pOIDCToken,
                  pAccessToken->pszAccessToken,
                  pszTenantSigningCert,
                  NULL,
                  VMCA_DEFAULT_CLOCK_TOLERANCE
                  );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAAllocateMemory(
                           sizeof(VMCA_OIDC_ACCESS_TOKEN_DETAILS),
                           &pToken
                           );
    BAIL_ON_VMCA_ERROR(dwError);

    pToken->pOIDCToken = pOIDCToken;
    pOIDCToken = NULL;

    *ppToken = pToken;

cleanup:
    return dwError;

error:
    goto cleanup;
}

static
DWORD
VMCAGetAccessTokenFromParameter(
    PSTR pszAccessTokenParameter,
    PVMCA_OIDC_ACCESS_TOKEN* ppAccessToken
    )
{
    DWORD dwError = 0;
    PVMCA_OIDC_ACCESS_TOKEN pAccessToken = NULL;
    PSTR pszNextToken = NULL;
    PSTR pszTokenType = NULL;

    if (IsNullOrEmptyString(pszAccessTokenParameter) ||
        !ppszAccessToken
       )
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    dwError = VMCAAllocateMemory(
                            sizeof(VMCA_OIDC_ACCESS_TOKEN),
                            (PVOID*)&pAccessToken
                            );
    BAIL_ON_VMCA_ERROR(dwError);

    pszTokenType = VMCAStringTokA(
                              pszAccessTokenParameter,
                              " ",
                              &pszNextToken
                              );

    if (pszTokenType)
    {
       if (VMCAStringCompareA(pszTokenType, "Bearer", FALSE))
       {
          pAccessToken->tokenType = VMCA_OIDC_ACCESS_TOKEN_TYPE_BEARER;
       }

       dwError = VMCAAllocateStringA(
                               pszNextToken,
                               &pAccessToken->pszAccessToken
                               );
       BAIL_ON_VMCA_ERROR(dwError);
    }

    *ppAccessToken = pAccessToken;
cleanup:
    return dwError;

error:
    if (ppAccessToken)
    {
        *ppAccessToken = NULL;
    }
    if (pAccessToken)
    {
        VMCA_SAFE_FREE_STRINGA(pAccessToken->pszAccessToken);
        VMCA_SAFE_FREE_MEMORY(pAccessToken);
    }
    goto cleanup;
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
