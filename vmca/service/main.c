/*
 * Copyright © 2012-2016 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
#include "includes.h"

static
VOID
PrintCurrentState(
	VOID
	);

static DWORD
VMCAParseArgs(
    int argc,
    char* argv[],
    PBOOL pbEnableSysLog
)
{
    DWORD dwError = ERROR_SUCCESS;
    int opt = 0;
    BOOL bEnableSysLog = FALSE;

    while ( (opt = getopt( argc, argv, VMCA_OPTIONS_VALID)) != EOF )
    {
        switch ( opt )
        {
            case VMCA_OPTION_ENABLE_SYSLOG:
                bEnableSysLog = TRUE;
                break;

            default:
                dwError = ERROR_INVALID_PARAMETER;
                BAIL_ON_VMCA_ERROR(dwError);
        }
    }

    if (pbEnableSysLog != NULL)
    {
        *pbEnableSysLog = bEnableSysLog;
    }

error:
    return dwError;
}

REST_PROCESSOR sVmcaHttpHandlers =
{
//    .pfnHandleRequest  = &VMCAHandleHttpRequest,
    .pfnHandleCreate = &VMCAHandleHttpRequest2,
    .pfnHandleRead = &VMCAHandleHttpRequest2,
    .pfnHandleUpdate = &VMCAHandleHttpRequest2,
    .pfnHandleDelete = &VMCAHandleHttpRequest2,
};

#ifndef _WIN32

REST_MODULE _vmca_rest_module[] =
{
    {
        "/vmca/crl",
        {VMCARESTGetCRL, NULL, NULL, NULL}
    },
    {
        "/vmca/certificates",
        {VMCARESTGetCRL, NULL, NULL, NULL}
    },
    {
        "/vmca/root",
        {VMCARESTGetRootCert, NULL, NULL, NULL}
    },
    {0}
};

uint32_t
vmca_rest_get_registration(
    PREST_MODULE *ppRestModule
    )
{
    *ppRestModule = _vmca_rest_module;
    return 0;
}

DWORD
VMCAHttpServiceStartup()
{
    uint32_t                         dwError = 0;
    PREST_API_DEF                    pApiDef = NULL;
    PREST_PROCESSOR                  pHandlers = &sVmcaHttpHandlers;
    PREST_CONF                       pConfig = NULL;
    PREST_API_MODULE                 pModule = NULL;

    MODULE_REG_MAP stRegMap[] =
    {
        {"vmca",     vmca_rest_get_registration},
        {NULL, NULL}
    };

    dwError = VMCAAllocateMemory(
            sizeof(REST_CONF),
            (PVOID*) &pConfig
            );

    pConfig->pSSLCertificate = VMCARESTSSLCERT;
    pConfig->pSSLKey = VMCARESTSSLKEY;
    pConfig->pServerPort = VMCARESTPORT;
    pConfig->pDebugLogFile = VMCARESTDEBUGLOGFILE;
    pConfig->pClientCount = VMCARESTCLIENTCNT;
    pConfig->pMaxWorkerThread = VMCARESTWORKERTHCNT;

    dwError = VmRESTInit(pConfig, NULL);
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = coapi_load_from_file(REST_API_SPEC, &pApiDef); //  TODO: Add REST_API_SPEC
    BAIL_ON_VMREST_ERROR(dwError);

    dwError = coapi_map_api_impl(pApiDef, stRegMap);
    BAIL_ON_VMREST_ERROR(dwError);

    for (pModule = pApiDef->pModules; pModule; pModule = pModule->pNext)
    {
        PREST_API_ENDPOINT pEndPoint = pModule->pEndPoints;
        for (; pEndPoint; pEndPoint = pEndPoint->pNext)
        {
            dwError = VmRESTRegisterHandler(pEndPoint->pszName,
                                    pHandlers,
                                    NULL);
            BAIL_ON_VMREST_ERROR(dwError);
        }

    }

    dwError = VMCASetApiDef(pApiDef);
    BAIL_ON_VMREST_ERROR(dwError);

//    dwError = rest_register_api_spec(pApiDef, &pHandlers);
//    BAIL_ON_VMREST_ERROR(dwError);
//
//
//    dwError = VmRESTRegisterHandler(
//                NULL,
//                pHandlers,
//                NULL
//                );
//    BAIL_ON_VMREST_ERROR(dwError);

    dwError = VmRESTStart();
    BAIL_ON_VMREST_ERROR(dwError);

cleanup:

    VMCA_SAFE_FREE_MEMORY(pConfig);
    return dwError;

error:
    goto cleanup;

}

void
VMCAHttpServiceShutdown()
{
    VmRESTStop();
    VmRESTShutdown();
}
#endif

int
main(
    int   argc,
    char* argv[]
    )
{
    DWORD dwError = 0;
    const char* pszSmNotify = NULL;
    int notifyFd = -1;
    int notifyCode = 0;
    int ret = -1;
    BOOL bEnableSysLog = FALSE;

    setlocale(LC_ALL, "");

    VMCABlockSelectedSignals();

    dwError = VMCAParseArgs(argc, argv, &bEnableSysLog);
    BAIL_ON_VMCA_ERROR(dwError);


    if (bEnableSysLog)
    {
        gVMCALogType = VMCA_LOG_TYPE_SYSLOG;
    }
    else
    {
        gVMCALogType = VMCA_LOG_TYPE_FILE;
    }

    dwError  = VMCAInitialize(0, 0);
    BAIL_ON_VMCA_ERROR(dwError);

    VMCA_LOG_INFO("VM Certificate Service started.");

    #ifndef _WIN32
    dwError = VMCAHttpServiceStartup();
    BAIL_ON_VMCA_ERROR(dwError);
    #endif
    VMCA_LOG_INFO("VM Certificate ReST Protocol started.");

    PrintCurrentState();

    // interact with likewise service manager (start/stop control)
    if ((pszSmNotify = getenv("LIKEWISE_SM_NOTIFY")) != NULL)
    {
        notifyFd = atoi(pszSmNotify);

        do
        {
            ret = write(notifyFd, &notifyCode, sizeof(notifyCode));

        } while (ret != sizeof(notifyCode) && errno == EINTR);

        if (ret < 0)
        {
            VMCA_LOG_ERROR("Could not notify service manager: %s (%i)",
                            strerror(errno),
                            errno);
            dwError = LwErrnoToWin32Error(errno);
            BAIL_ON_VMCA_ERROR(dwError);
        }

        close(notifyFd);
    }

    // main thread waits on signals
    dwError = VMCAHandleSignals();
    BAIL_ON_VMCA_ERROR(dwError);

    VMCA_LOG_INFO("VM Certificate Service exiting...");

cleanup:

    VMCAShutdown();
    #ifndef _WIN32
    VMCAHttpServiceShutdown();
    #endif
    return (dwError);

error:

    VMCA_LOG_ERROR("VM Certificate exiting due to error [code:%d]", dwError);

    goto cleanup;
}

static
VOID
PrintCurrentState(
	VOID
	)
{
	DWORD dwFuncLevel = VMCASrvGetFuncLevel();

    if (dwFuncLevel == VMCA_FUNC_LEVEL_INITIAL) {
        printf("VMCA Server Functional level is VMCA_FUNC_LEVEL_INITIAL\n");
    }

    if ((dwFuncLevel & VMCA_FUNC_LEVEL_SELF_CA) == VMCA_FUNC_LEVEL_SELF_CA) {
        printf("VMCA Server Functional level is VMCA_FUNC_LEVEL_SELF_CA\n");
    }
}
