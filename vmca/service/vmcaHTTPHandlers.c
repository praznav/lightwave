/*
 * Copyright © 2012-201666666 VMware, Inc.  All Rights Reserved.
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

#ifndef _WIN32

DWORD
VMCAHandleCRLRequest(
    VMCARequestObj                     pVMCARequest,
    PSTR*                              ppStatusCode,
    PSTR*                              ppResponsePayload
    )
{
    DWORD                            dwError = 0;

    if (!strcmp(pVMCARequest.method,"HEAD"))
    {
        dwError = VMCARESTGetServerVersion(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);
    } else if (!strcmp(pVMCARequest.method,"GET"))
    {
        dwError = VMCARESTGetCRL(
                    pVMCARequest,
                    ppStatusCode,
                    ppResponsePayload
                    );
        BAIL_ON_VMREST_ERROR(dwError);
    } else {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMREST_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}


DWORD
VMCAHandleRootRequest(
    VMCARequestObj                     pVMCARequest,
    PSTR*                              ppStatusCode,
    PSTR*                              ppResponsePayload
    )
{
    DWORD                            dwError = 0;

    if (!strcmp(pVMCARequest.method,"GET"))
    {
        dwError = VMCARESTGetRootCACertificate(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);

    } else if (!strcmp(pVMCARequest.method,"POST"))
    {
        dwError = VMCARESTSrvPublishRootCerts(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);
    } else if (!strcmp(pVMCARequest.method,"PUT"))
    {
        dwError = VMCARESTAddRootCertificate(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);
    } else if (!strcmp(pVMCARequest.method,"HEAD"))
    {
        dwError = VMCARESTGetServerVersion(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);
    } else {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMREST_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

DWORD
VMCAHandleCertRequest(
    VMCARequestObj                     pVMCARequest,
    PSTR*                              ppStatusCode,
    PSTR*                              ppResponsePayload
    )
{
    DWORD                            dwError = 0;

    if (!strcmp(pVMCARequest.method,"GET"))
    {
        dwError = VMCARESTEnumCertificates(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);
    } else if (!strcmp(pVMCARequest.method,"PUT"))
    {
        dwError = VMCARESTGetSignedCertificate(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);
    } else if (!strcmp(pVMCARequest.method,"DELETE"))
    {
        dwError = VMCARESTRevokeCertificate(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);
    } else if (!strcmp(pVMCARequest.method,"HEAD"))
    {
        dwError = VMCARESTGetServerVersion(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);
    } else {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMREST_ERROR(dwError);
    }

cleanup:

    return dwError;

error:
    goto cleanup;
}


DWORD
VMCAHandleOCSPRequest(
    VMCARequestObj                     pVMCARequest,
    PSTR*                              ppStatusCode,
    PSTR*                              ppResponsePayload
    )
{
    DWORD                            dwError = 0;

    if (!strcmp(pVMCARequest.method,"HEAD"))
    {
        dwError = VMCARESTGetOCSP(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);
    } else if (!strcmp(pVMCARequest.method,"GET"))
    {
        dwError = VMCARESTGetOCSP(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);
    } else {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMREST_ERROR(dwError);
    }
cleanup:

    return dwError;

error:
    goto cleanup;
}
DWORD
VMCAHandleVMCARequest(
    VMCARequestObj                     pVMCARequest,
    PSTR*                              ppStatusCode,
    PSTR*                              ppResponsePayload
    )
{
    DWORD                            dwError = 0;

    if (!strcmp(pVMCARequest.method,"HEAD"))
    {
        dwError = VMCARESTGetServerVersion(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);
    } else if (!strcmp(pVMCARequest.method,"GET"))
    {
        dwError = VMCARESTGetServerVersion(
                        pVMCARequest,
                        ppStatusCode,
                        ppResponsePayload
                        );
        BAIL_ON_VMREST_ERROR(dwError);
    } else {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMREST_ERROR(dwError);
    }
cleanup:

    return dwError;

error:
    goto cleanup;
}

DWORD
VMCASafeFreeJSONKeyValue (
    JSONKeyValue*       pResponse
    )
{
    int size;
    int counter;
    if (!pResponse)
    {
        return 0;
    }

    size = sizeof(pResponse)/sizeof(pResponse[0]);
    counter = 0;
    for (; counter < size; counter ++)
    {
        VMCA_SAFE_FREE_MEMORY(pResponse[0].key);
        VMCA_SAFE_FREE_MEMORY(pResponse[0].val);
    }
    VMCA_SAFE_FREE_MEMORY(pResponse);
    return 0;
}

DWORD
VMCASortJSONObjects(
    json_t*             root,
    JSONKeyValue**      ppResponse
    )
{
    DWORD               dwError         = 0;
    char                *buff;
    const char          *key;
    json_t              *value;
    int                 counter         = 0;
    int                 digits;
    int                 i;
    JSONKeyValue*       pResponse = *ppResponse;

    json_object_foreach(root, key, value)
    {
        switch (json_typeof(value)) {

            case JSON_OBJECT :
                dwError = 1;
                BAIL_ON_VMREST_ERROR(dwError);
                break;

            case JSON_ARRAY :
                dwError = 1;
                BAIL_ON_VMREST_ERROR(dwError);
                break;

            case JSON_STRING :
                dwError = VMCAAllocateMemory(
                        strlen(json_string_value(value)),
                        (PVOID*) &buff
                        );
                BAIL_ON_VMREST_ERROR(dwError);
                strcpy(buff, json_string_value(value));
                break;

            case JSON_INTEGER :
                i = (int) json_integer_value(value);
                digits = 0;
                while (i != 0 )
                {
                    i /= 10;
                    digits ++;
                }
                dwError = VMCAAllocateMemory(
                        (digits+1)*sizeof(char),
                        (PVOID*) &buff
                        );
                BAIL_ON_VMREST_ERROR(dwError);
                snprintf(buff, digits, "%" JSON_INTEGER_FORMAT, json_integer_value(value) );
                break;

            case JSON_REAL :
                dwError = VMCAAllocateMemory(
                        (1000)*sizeof(char),
                        (PVOID*) &buff
                        );
                BAIL_ON_VMREST_ERROR(dwError);
                snprintf(buff, 5, "%f", json_real_value(value) );
                break;

            case JSON_TRUE :
                dwError = VMCAAllocateMemory(
                        5*sizeof(char),
                        (PVOID*) &buff
                        );
                BAIL_ON_VMREST_ERROR(dwError);
                strcpy(buff, "true");
                break;

            case JSON_FALSE :
                dwError = VMCAAllocateMemory(
                        6*sizeof(char),
                        (PVOID*) &buff
                        );
                BAIL_ON_VMREST_ERROR(dwError);
                strcpy(buff, "false");
                break;

            case JSON_NULL :
                dwError = VMCAAllocateMemory(
                        5*sizeof(char),
                        (PVOID*) &buff
                        );
                BAIL_ON_VMREST_ERROR(dwError);
                strcpy(buff, "null");
                break;

            default :
                break;
        }
        dwError = VMCAAllocateMemory(
                sizeof(key),
                (PVOID*) &pResponse[counter].key
                );
        BAIL_ON_VMREST_ERROR(dwError);
        strcpy(pResponse[counter].key, key);
	pResponse[counter].val = buff;

        counter ++;
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}
DWORD
VMCAParseJsonInput (
    char*               pPayload,
    JSONKeyValue**      ppResponse
    )
{
    DWORD 		dwError		= 0;
    JSONKeyValue*       pResponse       = NULL;
    json_t              *root;
    json_error_t        error;
    int                 counter;

    root = json_loads(pPayload, 0, &error); // jansson library function

    if (!root)
    {
        printf ("error on line: %d: %s\n", error.line, error.text); // TODO: add this to log instead
        *ppResponse = pResponse;
        dwError =  1;
        BAIL_ON_VMREST_ERROR(dwError);
    }

    if (!json_is_object(root))
    {
        printf ( "You must input a JSON Object with each paramter as a key-value pair.\n" ); //TODO: add this to log instead
        *ppResponse = pResponse;
        dwError =  1;
        BAIL_ON_VMREST_ERROR(dwError);
    }

    dwError = VMCAAllocateMemory(
                5*sizeof(JSONKeyValue),
                (PVOID*) &pResponse
                );
    BAIL_ON_VMREST_ERROR(dwError);

    for (counter = 0; counter < 5; counter++)
    {
        pResponse[counter].key = NULL;
        pResponse[counter].val = NULL;
    }

    dwError = VMCASortJSONObjects(root, &pResponse);
    BAIL_ON_VMREST_ERROR(dwError);

    *ppResponse = pResponse;

cleanup:
    return dwError;

error:
    VMCASafeFreeJSONKeyValue (
        pResponse
        );
    goto cleanup;
}


DWORD
VMCAParseHttpHeader(
    PREST_REQUEST                       pRESTRequest,
    VMCARequestObj**                    ppVMCARequest
    )
{
    DWORD dwError                       = 0;
    PSTR  ptr                           = NULL;
    VMCARequestObj*                     pVMCARequest;

    dwError = VMCAAllocateMemory(
                sizeof(VMCARequestObj),
                (PVOID*) &pVMCARequest
                );
    BAIL_ON_VMREST_ERROR(dwError);

    pVMCARequest->debugFile = fopen ("/tmp/restDebug.log", "a");
    fprintf(pVMCARequest->debugFile, "Starting VMCA rest debug log\n");

    dwError = VmRESTGetHttpMethod(pRESTRequest, &ptr);
    BAIL_ON_VMREST_ERROR(dwError);
    pVMCARequest->method = ptr;

    dwError = VmRESTGetHttpURI(pRESTRequest, &ptr);
    BAIL_ON_VMREST_ERROR(dwError);
    pVMCARequest->uri = ptr;

    dwError = VmRESTGetHttpVersion(pRESTRequest, &ptr);
    BAIL_ON_VMREST_ERROR(dwError);
    pVMCARequest->ver = ptr;

    dwError = VmRESTGetHttpHeader(pRESTRequest,"Connection", &ptr);
    BAIL_ON_VMREST_ERROR(dwError);
    pVMCARequest->connection = ptr;

    dwError = VmRESTGetHttpHeader(pRESTRequest,"Transfer-Encoding", &ptr);
    BAIL_ON_VMREST_ERROR(dwError);
    pVMCARequest->transferEncoding = ptr;

    dwError = VmRESTGetHttpHeader(pRESTRequest,"Content-Length", &ptr);
    BAIL_ON_VMREST_ERROR(dwError);
    pVMCARequest->contentLength = ptr;

    *ppVMCARequest = pVMCARequest;
cleanup:

    return dwError;
error:
    VMCA_SAFE_FREE_MEMORY(pVMCARequest);

    goto cleanup;

}


DWORD
VMCAGetPayload(
    PREST_REQUEST                       pRESTRequest,
    VMCARequestObj*                     pVMCARequest
    )
{
    DWORD                               dwError = 0;
    int                                 buffersize = 4096;
    int                                 currentsize = 0;
    char                                buffer[buffersize];
    DWORD                               doneWithPayload = 0;


    memset(buffer, '\0', buffersize);


//    dwError = VMCAReallocateMemory(
//                    (PVOID) *pVMCARequest->payload,
//                    (PVOID*) pVMCARequest->payload,
//                    100
//                    );
//    BAIL_ON_VMREST_ERROR(dwError);
//    strcat(*pVMCARequest->payload, "[{this: \"test\" }]");

    while(doneWithPayload != 1)
    {
        dwError = VmRESTGetHttpPayload(
                    pRESTRequest,
                    buffer,
                    &doneWithPayload
                    );
        BAIL_ON_VMREST_ERROR(dwError);
        if (strlen(buffer) > 0)
        {
            currentsize += strlen(buffer);
            dwError = VMCAReallocateMemory(
                        (PVOID) *pVMCARequest->payload,
                        (PVOID*) pVMCARequest->payload,
                        currentsize
                        );
            BAIL_ON_VMREST_ERROR(dwError);
            strcat(*pVMCARequest->payload, buffer);
        }
        memset(buffer, '\0', buffersize);
    }

cleanup:

    return dwError;

error:

    goto cleanup;

}


DWORD
VMCAParseHttpURI(
    VMCARequestObj*                     pVMCARequest,
    PSTR*                               ppStatusCode,
    PSTR*                               ppResponsePayload
    )
{
    DWORD                               dwError = 0;
    PSTR                                pStatusCode = NULL;
    PSTR                                pResponsePayload = NULL;

    if (strcasestr(pVMCARequest->uri,VMCA_CRL_URI) != NULL)
    {
        dwError = VMCAHandleCRLRequest(
                    *pVMCARequest,
                    &pStatusCode,
                    &pResponsePayload
                    );
        BAIL_ON_VMREST_ERROR(dwError);
    } else if (strcasestr(pVMCARequest->uri,VMCA_ROOT_URI) != NULL)
    {
        dwError = VMCAHandleRootRequest(
                    *pVMCARequest,
                    &pStatusCode,
                    &pResponsePayload
                    );
        BAIL_ON_VMREST_ERROR(dwError);
    } else if (strcasestr(pVMCARequest->uri,VMCA_CERTS_URI) != NULL)
    {
        dwError = VMCAHandleCertRequest(
                    *pVMCARequest,
                    &pStatusCode,
                    &pResponsePayload
                    );
        BAIL_ON_VMREST_ERROR(dwError);
    } else if (strcasestr(pVMCARequest->uri,VMCA_OCSP_URI) != NULL)
    {
        dwError = VMCAHandleOCSPRequest(
                    *pVMCARequest,
                    &pStatusCode,
                    &pResponsePayload
                    );
        BAIL_ON_VMREST_ERROR(dwError);
    } else if (strcasestr(pVMCARequest->uri,VMCA_URI) != NULL)
    {
        dwError = VMCAHandleVMCARequest(
                    *pVMCARequest,
                    &pStatusCode,
                    &pResponsePayload
                    );
        BAIL_ON_VMREST_ERROR(dwError);
    }else {
        // TODO: dwError
    }

    *ppStatusCode = pStatusCode;
    *ppResponsePayload = pResponsePayload;

cleanup:

    return dwError;

error:

    goto cleanup;

}

DWORD
VMCASetResponseHeaders(
    PREST_RESPONSE*                     ppResponse,
    PSTR                                pStatusCode
    )
{
    DWORD                               dwError = 0;

    dwError = VmRESTSetHttpHeader(ppResponse, "VMware", "VMCA");
    BAIL_ON_VMREST_ERROR(dwError);
    dwError = VmRESTSetHttpHeader(ppResponse, "Location", "United States");
    BAIL_ON_VMREST_ERROR(dwError);
    dwError = VmRESTSetHttpStatusCode(ppResponse, pStatusCode);
    BAIL_ON_VMREST_ERROR(dwError);
    dwError = VmRESTSetHttpStatusVersion(ppResponse,"HTTP/1.1");
    BAIL_ON_VMREST_ERROR(dwError);
    dwError = VmRESTSetHttpReasonPhrase(ppResponse,"OK");
    BAIL_ON_VMREST_ERROR(dwError);
    dwError = VmRESTSetHttpHeader(ppResponse, "Unix", "Linux");
    BAIL_ON_VMREST_ERROR(dwError);
    dwError = VmRESTSetHttpHeader(ppResponse, "Connection", "close");
    BAIL_ON_VMREST_ERROR(dwError);

cleanup:

    return dwError;

error:

    goto cleanup;

}


DWORD
VMCASetResponsePayload(
    PREST_RESPONSE*                     ppResponse,
    PSTR                                pResponsePayload
    )
{
    DWORD                               dwError = 0;
    DWORD                               temp = 0;

    dwError = VmRESTSetHttpHeader(
                    ppResponse,
                    "Transfer-Encoding",
                    "chunked"
                    );
    BAIL_ON_VMREST_ERROR(dwError);
    dwError = VmRESTSetHttpPayload(
                ppResponse,
                pResponsePayload,
                strlen(pResponsePayload),
                &temp
                );
    BAIL_ON_VMREST_ERROR(dwError);
    dwError = VmRESTSetHttpPayload(
                ppResponse,
                "\n\n",
                2,
                &temp
                );
    BAIL_ON_VMREST_ERROR(dwError);
    dwError = VmRESTSetHttpPayload(ppResponse, "0",0, &temp );
    BAIL_ON_VMREST_ERROR(dwError);


cleanup:

    return dwError;

error:

    goto cleanup;

}

DWORD
VMCAHandleHttpRequest(
    PREST_REQUEST                       pRESTRequest,
    PREST_RESPONSE*                     ppResponse
    )
{
    DWORD                               dwError = 0;
    PSTR                                pStatusCode = NULL;
    PSTR                                pResponsePayload = NULL;
    PSTR                                pPayloadObject = NULL;
    VMCARequestObj*                     pVMCARequest = NULL;

    //dwError = VMCARESTVerifyBasicAuth(
    dwError = VMCARESTVerifyKrbAuth(
                    pRESTRequest,
                    ppResponse
                    );
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = VMCAParseHttpHeader(
                    pRESTRequest,
                    &pVMCARequest
                    );
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = VMCAAllocateMemory(
                    sizeof(char*),
                    (PVOID*) &pVMCARequest->payload
                    );
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = VMCAGetPayload(
                    pRESTRequest,
                    pVMCARequest
                    );
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = VMCAParseJsonInput(
                    *pVMCARequest->payload,
                    &pVMCARequest->params
                    );
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = VMCAParseHttpURI(
                    pVMCARequest,
                    &pStatusCode,
                    &pResponsePayload
                    );
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = VMCASetResponseHeaders(
                    ppResponse,
                    pStatusCode
                    );
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = VMCASetResponsePayload(
                    ppResponse,
                    pResponsePayload
                    );
    BAIL_ON_VMREST_ERROR(dwError);

    fprintf(pVMCARequest->debugFile, "Ending VMCA rest debug log\n");

cleanup:
//    fclose(pVMCARequest->debugFile);
    VMCA_SAFE_FREE_MEMORY(pResponsePayload);
    VMCA_SAFE_FREE_MEMORY(pStatusCode);
    if (pVMCARequest)
    {
        VMCASafeFreeJSONKeyValue (
            pVMCARequest->params
            );
    VMCA_SAFE_FREE_MEMORY(pVMCARequest->payload);
    }
    VMCA_SAFE_FREE_MEMORY(pVMCARequest);
    VMCA_SAFE_FREE_MEMORY(pPayloadObject);
    return dwError;

error:
    // Handle Errors properly for status code
//    VMCASetResponseHeaders(
//                ppResponse,
//                "400"
//                );
//
//     VMCASetResponsePayload(
//                ppResponse,
//                "There was an error."
//                );

    goto cleanup;
}


#endif
