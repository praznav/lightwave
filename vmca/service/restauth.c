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
    PVMCA_AUTHORIZATION_PARAM* ppAuthorization
    );

static
DWORD
VMCAFindRestAuthMethod(
    VMCA_AUTHORIZATION_TYPE authType,
    PDWORD pdwIdx
    );

DWORD
VMCARESTGetAccessToken(
      pRESTRequest pRESTRequest,
      PVMCA_ACCESS_TOKEN* ppAccessToken
      )
{
    DWORD dwError = 0;
    PSTR pszAccessTokenParameter = NULL;
    PVMCA_AUTHORIZATION_PARAM pAuthorization = NULL;
    PVMCA_ACCESS_TOKEN pAccessToken = NULL;

    if (!pRESTRequest || !ppAccessToken)
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
                                        &pAuthorization
                                        );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAVerifyAccess(
                        pAuthorization,
                        &pAccessToken
                        );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppAccessToken = pAccessToken;

cleanup:
    VMCA_SAFE_FREE_STRINGA(pszAccessTokenParameter);
    if (pAuthorization)
    {
        VMCAFreeAuthorizationParam(pAuthorization);
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


cleanup:
    return dwError;
error:
    goto cleanup;
}

DWORD
VMCAVerifyAccess(
      PVMCA_AUTHORIZATION_PARAM pAuthorization,
      PVMCA_ACCESS_TOKEN* ppAccessToken
      )
{
    DWORD dwError = 0;
    DWORD dwIdx = 0;

    dwError = VMCAFindRestAuthMethod(
                              pAuthorization->tokenType,
                              &dwIdx
                              );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = gVMCAAccessTokenMethods[dwIdx].pfnVerify(
                                               pAuthorization,
                                               &ppAccessToken
                                               );
    BAIL_ON_VMCA_ERROR(dwError);

cleanup:
    return dwError;

error:
    if (ppAccessToken)
    {
        *ppAccessToken = NULL;
    }
    goto cleanup;
}

BOOL
VMCACheckAccess(
      PVMCA_AUTHORIZATION_PARAM pAuthorization,
      PSTR pszUserName,
      PSTR pszGroupName
      )
{
    return TRUE;
}

VOID
VMCAFreeAuthorizationParam(
      PVMCA_AUTHORIZATION_PARAM pAuthorization
      )
{
    if (pAuthorization)
    {
        VMCA_SAFE_FREE_STRINGA(pAuthorization->pszAuthorizationToken);
        VMCA_SAFE_FREE_MEMORY(pAuthorization);
    }
}

VOID
VMCAFreeAccessToken(
      PVMCA_ACCESS_TOKEN pAccessToken
      )
{
    if (pAccessToken)
    {
        DWORD dwIdx = 0;
        VMCA_SAFE_FREE_STRINGA(pAccessToken->pszSubjectName);
        VMCAFreeStringA(
              pAccessToken->pszGroups,
              pAccessToken->dwGroupSize
              );
        dwError = VMCAFindRestAuthMethod(pAccessToken->tokenType, &dwIdx);
        if (!dwError)
        {
            gVMCARestAuthFunction[dwIdx].pfnFree(pAccessToken);
        }
        VMCA_SAFE_FREE_MEMORY(pAccessToken);
    }
}

static
DWORD
VMCAGetAccessTokenFromParameter(
    PSTR pszAccessTokenParameter,
    PVMCA_AUTHORIZATION_PARAM* ppAuthorization
    )
{
    DWORD dwError = 0;
    PVMCA_AUTHORIZATION_PARAM pAccessToken = NULL;
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
          pAccessToken->tokenType = VMCA_AUTHORIZATION_TYPE_BEARER_TOKEN;
       }

       if (VMCAStringCompareA(pszTokenType, "Negotiate", FALSE))
       {
          pAccessToken->tokenType = VMCA_AUTHORIZATION_TOKEN_TYPE_KRB;
       }
    }

    dwError = VMCAAllocateStringA(
                           pszNextToken,
                           &pAccessToken->pszAccessToken
                           );
    BAIL_ON_VMCA_ERROR(dwError);

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
VMCAFindRestAuthMethod(
    VMCA_AUTHORIZATION_TYPE authType,
    PDWORD pdwIdx
    )
{
    DWORD dwError = 0;
    DWORD dwIndex = 0;
    BOOL bFound = FALSE;

    if (!pdwIdx)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    for (;dwIndex < VMCA_AUTHORIZATION_TOKEN_TYPE_MAX; ++dwIndex)
    {
        if (gVMCAAccessTokenMethods[dwIndex].type == authType)
        {
            bFound = TRUE;
            break;
        }
    }

    if (bFound)
    {
        *pdwIdx = dwIndex;
    }
    else
    {
        dwError = ERROR_INVALID_FUNCTION;
        BAIL_ON_VMCA_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    if (pdwIdx)
    {
        *pdwIdx = 0;
    }
    goto cleanup;
}
