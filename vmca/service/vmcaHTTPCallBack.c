#include "includes.h"

#ifndef _WIN32

DWORD
VMCAWritePayload(
    char*                               payloadContents,
    char*                               contentName,
    PSTR*                               ppResponsePayload
    )
{
    DWORD dwError                       = 0;
    char* pResponsePayload              = NULL;

    if (payloadContents == NULL )
    {
        dwError = VMCAAllocateMemory(
                20,
                (PVOID*) &pResponsePayload
                );
        BAIL_ON_VMCA_ERROR(dwError);

        strcpy(pResponsePayload, "{Success: \"success\"}");
    } else
    {
        int contentLength                   = strlen(payloadContents);
        int nameLength                      = strlen(contentName);
        int totalLength                     =   contentLength +
                                                nameLength +
                                                6;

        dwError = VMCAAllocateMemory(
                totalLength,
                (PVOID*) &pResponsePayload
                );
        BAIL_ON_VMCA_ERROR(dwError);

        strcpy(pResponsePayload, "{");
        strcpy(pResponsePayload+1, contentName);
        strcpy(pResponsePayload+nameLength+1, ": \"");
        strcpy(pResponsePayload+4+nameLength, payloadContents);
        strcpy(pResponsePayload+4+contentLength+nameLength, "\"}");
    }
    *ppResponsePayload = pResponsePayload;
cleanup:

    return dwError;
error:
    if (pResponsePayload)
    {
        VMCA_SAFE_FREE_MEMORY(pResponsePayload);
    }
    goto cleanup;
}

DWORD
VMCAWriteStatus(
    char*                               status,
    PSTR*                               ppStatusCode
    )
{
    DWORD dwError               = 0;
    char* pStatusCode           = NULL;

    dwError = VMCAAllocateMemory(
            strlen(status),
            (PVOID*) &pStatusCode
            );
    BAIL_ON_VMREST_ERROR(dwError);
    strcpy(pStatusCode,status);

    *ppStatusCode = pStatusCode;
cleanup:
    return dwError;

error:
    if (pStatusCode)
    {
        VMCA_SAFE_FREE_MEMORY(pStatusCode);
    }
    goto cleanup;
}

DWORD
mystrtoi(
    const char*                         pStr,
    int*                                pInt
    )
{
    DWORD dwError               = 0;
    char                        *endptr;
    errno                       = 0;

    long l                      = strtol(pStr, &endptr, 0);

    if (
        errno == ERANGE ||
        *endptr != '\0' ||
        pStr == endptr
        )
    {
        dwError = 1;//TODO: fix
        BAIL_ON_VMREST_ERROR(dwError);
    }

    // Only needed if sizeof(int) < sizeof(long)
    if  (
        l < INT_MIN ||
        l > INT_MAX
        )
    {
        dwError = 2;//TODO: fix
        BAIL_ON_VMREST_ERROR(dwError);
    }

    *pInt = (int) l;

cleanup:

    return dwError;

error:

    goto cleanup;
}

DWORD
VMCARESTGetCRL(
    const char *pszInputJson,
    char **ppszOutputJson
    )
{
    DWORD dwError                       = 0;
    VMCA_FILE_BUFFER* pTempCRLData      = NULL;
    unsigned int dwFileOffset           = 0;
    unsigned int dwSize                 = 65535;
    char *pszOutputJson;

    dwError = VMCAGetCRL(
            dwFileOffset,
            dwSize,
            &pTempCRLData
            );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWritePayload(
            pTempCRLData->buffer,
            "crl",
            &pszOutputJson
            );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppszOutputJson = pszOutputJson;

cleanup:
    if (pTempCRLData != NULL)
    {
        VMCA_SAFE_FREE_MEMORY (pTempCRLData->buffer);
    }

    return dwError;

error:
    goto cleanup;

}

DWORD
VMCARESTGetCRL2(
    PSTR*                               ppCRLResponse
    )
{
    DWORD dwError                       = 0;
    VMCA_FILE_BUFFER* pTempCRLData      = NULL;
    unsigned int dwFileOffset           = 0;
    unsigned int dwSize                 = 65535;

    dwError = VMCAGetCRL(
            dwFileOffset,
            dwSize,
            &pTempCRLData
            );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppCRLResponse = pTempCRLData->buffer;

cleanup:
    if (pTempCRLData != NULL)
    {
        VMCA_SAFE_FREE_MEMORY (pTempCRLData->buffer);
    }
    return dwError;

error:
    goto cleanup;
}

DWORD
VMCARESTGetCRL3(
    VMCARequestObj                      request,
    PSTR*                               ppStatusCode,
    PSTR*                               ppResponsePayload
    )
{
    DWORD dwError                       = 0;
    VMCA_FILE_BUFFER* pTempCRLData      = NULL;
    char* pStatusCode                   = NULL;
    char* pResponsePayload              = NULL;
    unsigned int dwFileOffset           = 0;
    unsigned int dwSize                 = 65535;

    dwError = VMCAGetCRL(
            dwFileOffset,
            dwSize,
            &pTempCRLData
            );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWritePayload(
            pTempCRLData->buffer,
            "crl",
            &pResponsePayload
            );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWriteStatus(
            "200",
            &pStatusCode
            );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppResponsePayload = pResponsePayload;
    *ppStatusCode = pStatusCode;
cleanup:
    if (pTempCRLData != NULL)
    {
        VMCA_SAFE_FREE_MEMORY (pTempCRLData->buffer);
    }
    return dwError;
error:
    // TODO: set status code properly based on error
    if (pStatusCode != NULL)
    {
        VMCA_SAFE_FREE_MEMORY (pStatusCode);
    }
    goto cleanup;
}

DWORD
VMCARESTGetRootCert(
    const char *pszInputJson,
    char **ppszOutputJson
    )
{
    DWORD dwError                       = 0;
    PVMCA_CERTIFICATE pTempCertificate  = NULL;
    char* pResponsePayload              = NULL;
    DWORD dwCertLength                  = 0;

    dwError = VMCAGetRootCACertificate(
            &dwCertLength,
            &pTempCertificate
            );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWritePayload(
            pTempCertificate,
            "certificate",
            &pResponsePayload
            );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppszOutputJson = pResponsePayload;

cleanup:
    if ( pTempCertificate != NULL )
    {
        VMCA_SAFE_FREE_MEMORY (pTempCertificate);
    }
    return dwError;

error:

    goto cleanup;
}

DWORD
VMCARESTGetRootCACertificate(
    VMCARequestObj                      request,
    PSTR*                               ppStatusCode,
    PSTR*                               ppResponsePayload
    )
{
    DWORD dwError                       = 0;
    PVMCA_CERTIFICATE pTempCertificate  = NULL;
    char* pStatusCode                   = NULL;
    char* pResponsePayload              = NULL;
    DWORD dwCertLength                  = 0;

    dwError = VMCAGetRootCACertificate(
            &dwCertLength,
            &pTempCertificate
            );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWritePayload(
            pTempCertificate,
            "certificate",
            &pResponsePayload
            );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWriteStatus(
            "200",
            &pStatusCode
            );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppResponsePayload = pResponsePayload;
    *ppStatusCode = pStatusCode;
cleanup:
    if ( pTempCertificate != NULL )
    {
        VMCA_SAFE_FREE_MEMORY (pTempCertificate);
    }
    return dwError;
error:
    if ( pStatusCode != NULL )
    {
        VMCA_SAFE_FREE_MEMORY (pStatusCode);
    }
    // TODO: set status code properly based on error
    goto cleanup;
}

DWORD
VMCARESTSrvPublishRootCerts(
    VMCARequestObj                      request,
    PSTR*                               ppStatusCode,
    PSTR*                               ppResponsePayload
    )
{
    DWORD dwError                       = 0;
    char* pStatusCode                   = NULL;
    char* pResponsePayload              = NULL;

    dwError = VMCASrvPublishRootCerts();
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWritePayload(
            NULL,
            NULL,
            &pResponsePayload
            );
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = VMCAWriteStatus(
            "201",
            &pStatusCode
            );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppResponsePayload = pResponsePayload;
    *ppStatusCode = pStatusCode;
cleanup:
    return dwError;
error:
    if (pResponsePayload != NULL)
    {
        VMCA_SAFE_FREE_MEMORY (pResponsePayload);
    }
    if ( pStatusCode != NULL )
    {
        VMCA_SAFE_FREE_MEMORY (pStatusCode);
    }    // TODO: set status code properly based on error
    goto cleanup;
}

DWORD
VMCARESTAddRootCertificate(
    VMCARequestObj                      request,
    PSTR*                               ppStatusCode,
    PSTR*                               ppResponsePayload
    )
{
    DWORD dwError                               = 0;
    char* pStatusCode                           = NULL;
    char* pResponsePayload                      = NULL;
    unsigned char* pszRootCertificate           = NULL;
    unsigned char* pszPrivateKey                = NULL;
    PWSTR pszPassPhrase                         = NULL;
    unsigned int dwOverWrite                    = 0;
    const char* certString                      = "Cert";
    const char* privKeyString                   = "PrivateKey";
    const char* overwriteString                 = "Overwrite";
    const int paramSize                         = 5;
    int i;

    for ( i = 0; i < paramSize; i++ )
    {
        if (request.params+i != NULL && request.params[i].key != NULL )
        {
            if ( !strcasecmp(request.params[i].key, certString) )
            {
                pszRootCertificate = request.params[i].val;
            } else
            if ( !strcasecmp(request.params[i].key, privKeyString) )
            {
                pszPrivateKey = request.params[i].val;
            } else
            if ( !strcasecmp(request.params[i].key, overwriteString) )
            {
                dwError = mystrtoi(
                    request.params[i].val,
                    &dwOverWrite
                    );
                BAIL_ON_VMCA_ERROR(dwError);
            }
        }
    }

    dwError = VMCAAddRootCertificate(
            pszRootCertificate,
            pszPassPhrase,      // can be left null
            pszPrivateKey,
            dwOverWrite
            );
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = VMCAWritePayload(
            NULL,
            NULL,
            &pResponsePayload
            );
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = VMCAWriteStatus(
            "201",
            &pStatusCode
            );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppStatusCode = pStatusCode;
    *ppResponsePayload = pResponsePayload;
cleanup:
    return dwError;
error:
    if (pResponsePayload != NULL)
    {
        VMCA_SAFE_FREE_MEMORY (pResponsePayload);
    }
    if ( pStatusCode != NULL )
    {
        VMCA_SAFE_FREE_MEMORY (pStatusCode);
    }    // TODO: set status code properly based on error
    goto cleanup;
}

DWORD
VMCARESTEnumCertificates(
    VMCARequestObj                      request,
    PSTR*                               ppStatusCode,
    PSTR*                               ppResponsePayload
    )
{
    DWORD dwError                               = 0;
    char* pStatusCode                           = NULL;
    char* pResponsePayload                      = NULL;
    unsigned int dwStartIndex                   = 0;
    unsigned int dwNumCertificates              = 2;
    VMCA_CERTIFICATE_ARRAY* pTempCertArray      = NULL;
    CERTIFICATE_STATUS dwStatus                 = CERTIFICATE_ALL;
    const char* flagString                      = "Flag";
    const char* numberString                    = "Number";
    int paramSize                               = 5;
    int i;

    for ( i = 0; i < paramSize; i++ )
    {
        if (request.params!= NULL && request.params[i].key != NULL )
        {
            if ( !strcasecmp(request.params[i].key, flagString) )
            {
                if( !strcasecmp(request.params[i].val, "all") )
                {
                    dwStatus = CERTIFICATE_ALL;
                } else if ( !strcasecmp(request.params[i].val, "active") )
                {
                    dwStatus = CERTIFICATE_ACTIVE;
                } else if ( !strcasecmp(request.params[i].val, "revoked") )
                {
                    dwStatus = CERTIFICATE_REVOKED;
                } else if ( !strcasecmp(request.params[i].val, "expired") )
                {
                    dwStatus = CERTIFIFCATE_EXPIRED;
                }
            } else
            if ( !strcasecmp(request.params[i].key, numberString) )
            {
                dwError = mystrtoi(
                    request.params[i].val,
                    &dwNumCertificates
                    );
                BAIL_ON_VMREST_ERROR(dwError);
            }
        }
    }

    dwError = VMCAEnumCertificates(
            dwStartIndex,
            dwNumCertificates,
            dwStatus,
            &pTempCertArray
            );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWriteStatus(
            "200",
            &pStatusCode
            );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppStatusCode = pStatusCode;

    if (pTempCertArray->certificates == NULL)
    {
        dwError = VMCAWritePayload(
                "empty",
                "empty",
                &pResponsePayload
                );
        BAIL_ON_VMCA_ERROR(dwError);

    } else {

        dwError = VMCAAllocateMemory(
                (
                        pTempCertArray->dwCount
                        *strlen(pTempCertArray->certificates[0].pCert)
                ) + pTempCertArray->dwCount,
                (PVOID*) &pResponsePayload
                );

        for (i = 0; i < (int)pTempCertArray->dwCount; i += 1)
        {
            strcpy(
                pResponsePayload + (i*strlen(pTempCertArray->certificates[0].pCert) + i),
                pTempCertArray->certificates[i].pCert
                );
            strcpy(
                pResponsePayload + ((i+1)*strlen(pTempCertArray->certificates[0].pCert) + i),
                "\n"
                );
        }
    }
    *ppResponsePayload = pResponsePayload;
cleanup:
    if (pTempCertArray)
    {
        VMCAFreeCertificateArray(pTempCertArray);
    }

    return dwError;
error:

    // TODO: set status code properly based on error
    goto cleanup;
}


DWORD
VMCARESTGetSignedCertificate(
    VMCARequestObj                      request,
    PSTR*                               ppStatusCode,
    PSTR*                               ppResponsePayload
    )
{
    DWORD dwError                                       = 0;
    char* pStatusCode                                   = NULL;
    char* pResponsePayload                              = NULL;
    unsigned char *pszPEMEncodedCSRRequest              = 0;
    unsigned int dwNotBefore                            = 0;
    unsigned int dwNotAfter                             = 0;
//    unsigned int duration                               = 0;
    VMCA_CERTIFICATE_CONTAINER* pTempCertContainer      = NULL;
//    const int paramSize                                 = 5;
//    const char *CSRString                               = "CSRRequest";
//    const char *DurationString                          = "Duration";
//    int i;

    dwError = VMCAGetSignedCertificate(
            pszPEMEncodedCSRRequest,
            dwNotBefore,
            dwNotAfter,
            &pTempCertContainer
            );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWritePayload(
            pTempCertContainer->pCert,
            "certificate",
            &pResponsePayload
            );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWriteStatus(
            "200",
            &pStatusCode
            );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppResponsePayload = pResponsePayload;
    *ppStatusCode = pStatusCode;
cleanup:
    VMCAFreeCertificateContainer(pTempCertContainer);
    return dwError;
error:
    if (pResponsePayload != NULL)
    {
        VMCA_SAFE_FREE_MEMORY (pResponsePayload);
    }
    if ( pStatusCode != NULL )
    {
        VMCA_SAFE_FREE_MEMORY (pStatusCode);
    }
    // TODO: set status code properly based on error
    goto cleanup;
}

DWORD
VMCARESTRevokeCertificate(
    VMCARequestObj                      request,
    PSTR*                               ppStatusCode,
    PSTR*                               ppResponsePayload
    )
{
    DWORD dwError                                       = 0;
    char* pStatusCode                                   = NULL;
    char* pResponsePayload                              = NULL;
    unsigned char *pszCertificate                       = 0;
    const int paramSize                                 = 5;
    const char* certString                              = "Cert";
    int i;

    for ( i = 0; i < paramSize; i++ )
    {
        if ( request.params[i].key != NULL )
        {
            if ( !strcasecmp(request.params[i].key, certString) )
            {
                pszCertificate = request.params[i].val;
            }
        }
    }

    dwError = VmcaSrvRevokeCertificate(
            NULL,
            pszCertificate,
            VMCA_CRL_REASON_UNSPECIFIED
            );
    BAIL_ON_VMCA_ERROR(dwError);
    dwError = VMCAWritePayload(
            NULL,
            NULL,
            &pResponsePayload
            );
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = VMCAWriteStatus(
            "201",
            &pStatusCode
            );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppResponsePayload = pResponsePayload;
    *ppStatusCode = pStatusCode;
cleanup:
    return dwError;
error:
    if ( pResponsePayload != NULL)
    {
        VMCA_SAFE_FREE_MEMORY(pResponsePayload);
    }
    if ( pStatusCode != NULL)
    {
        VMCA_SAFE_FREE_MEMORY(pStatusCode);
    }
    // TODO: set status code properly based on error
    goto cleanup;
}

DWORD
VMCARESTGetOCSP (
    VMCARequestObj                      request,
    PSTR*                               ppStatusCode,
    PSTR*                               ppResponsePayload
    )
{
    DWORD dwError                               = 0;
    VMCA_FILE_BUFFER* pTempCRLData              = NULL;
    char* pStatusCode                           = NULL;
    char* pResponsePayload                      = NULL;
    unsigned char *pszCertificate               = 0;
    unsigned int dwFileOffset                   = 0;
    unsigned int dwSize                         = 65535;
    unsigned int dwStartIndex                   = 0;
    unsigned int dwNumCertificates              = 10;
    VMCA_CERTIFICATE_ARRAY* pTempCertArray      = NULL;
    CERTIFICATE_STATUS dwStatus                 = CERTIFICATE_ALL;
    int i                                       = 0;
    int foundCert                               = 0;
    int paramSize                               = 5;
    const char* certString                      = "certificate";

    for ( i = 0; i < paramSize; i++ )
    {
        if ( request.params[i].key != NULL )
        {
            if ( !strcasecmp(request.params[i].key, certString) )
            {
                pszCertificate = request.params[i].val;
            }
        }
    }
    if (pszCertificate == 0)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMCA_ERROR(dwError);
    }

    dwError = VMCAGetCRL(
            dwFileOffset,
            dwSize,
            &pTempCRLData
            );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAEnumCertificates(
            dwStartIndex,
            dwNumCertificates,
            dwStatus,
            &pTempCertArray
            );
    BAIL_ON_VMCA_ERROR(dwError);

    if (strstr(pTempCRLData->buffer, pszCertificate) )
    {
        dwError = VMCAWritePayload (
                "revoked",
                "certificate status",
                &pResponsePayload
                );
        BAIL_ON_VMCA_ERROR(dwError);
    } else
    {
        foundCert = 0;
        for (i = 0; i < (int)pTempCertArray->dwCount; i += 1)
        {
            if (strstr(pTempCertArray->certificates[i].pCert, pszCertificate) )
            {
                foundCert = 1;
                i = (int)pTempCertArray->dwCount;
            }
        }
        if (foundCert)
        {
            dwError = VMCAWritePayload (
                    "active",
                    "certificate status",
                    &pResponsePayload
                    );
            BAIL_ON_VMCA_ERROR(dwError);
        } else
        {
            dwError = VMCAWritePayload (
                    "unknown",
                    "certificate status",
                    &pResponsePayload
                    );
            BAIL_ON_VMCA_ERROR(dwError);

        }
    }

    dwError = VMCAWriteStatus(
            "200",
            &pStatusCode
            );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppResponsePayload = pResponsePayload;
    *ppStatusCode = pStatusCode;
cleanup:
    if (pTempCRLData != NULL)
    {
        VMCA_SAFE_FREE_MEMORY (pTempCRLData->buffer);
    }
    if (pTempCertArray)
    {
        VMCAFreeCertificateArray(pTempCertArray);
    }

    return dwError;
error:
    VMCA_SAFE_FREE_MEMORY (pResponsePayload);
    VMCA_SAFE_FREE_MEMORY (pStatusCode);
    // TODO: set status code properly based on error
    goto cleanup;
}

DWORD
VMCARESTGetServerVersion (
    VMCARequestObj                      request,
    PSTR*                               ppStatusCode,
    PSTR*                               ppResponsePayload
    )
{
    DWORD dwError                       = 0;
    char* pResponsePayload              = NULL;
    char* pStatusCode                   = NULL;
    char* pTempServerVersion            = NULL;

    dwError = VMCAGetServerVersion(&pTempServerVersion);
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWritePayload (
            pTempServerVersion,
            "version",
            &pResponsePayload
            );
    BAIL_ON_VMCA_ERROR(dwError);

    dwError = VMCAWriteStatus(
            "200",
            &pStatusCode
            );
    BAIL_ON_VMCA_ERROR(dwError);

    *ppResponsePayload = pResponsePayload;
    *ppStatusCode = pStatusCode;
cleanup:
    VMCA_SAFE_FREE_STRINGA(pTempServerVersion);
    return dwError;
error:
    VMCA_SAFE_FREE_MEMORY (pResponsePayload);
    VMCA_SAFE_FREE_MEMORY (pStatusCode);
    // TODO: set status code properly based on error
    goto cleanup;
}
#endif
