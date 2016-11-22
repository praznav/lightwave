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



/*
 * Module Name: VMCA
 *
 * Filename: structs.h
 *
 * Abstract:
 *
 * Structure definitions
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    VMCAD_STARTUP = 0,
    VMCAD_RUNNING,
    VMCA_SHUTDOWN
} VMCA_SERVER_STATE;

typedef struct _VMCA_ENDPOINT
{
    PCSTR pszProtSeq;
    PCSTR pszEndpoint;
} VMCA_ENDPOINT, *PVMCA_ENDPOINT;

typedef PVOID (*PFN_VMCA_THR_FUNC)(PVOID pData);

typedef struct _VMCA_THREAD_DATA
{
    pthread_mutex_t   mutex;
    pthread_mutex_t*  pMutex;

    pthread_cond_t    cond;
    pthread_cond_t*   pCond;

    BOOLEAN           bShutdown;

    PVOID             pData;

} VMCA_THREAD_DATA, *PVMCA_THREAD_DATA;

typedef struct _VMCA_THREAD
{
	LONG              refCount;

    pthread_t         thread;
    pthread_t*        pThread;

    PVMCA_THREAD_DATA pThrData;

} VMCA_THREAD, *PVMCA_THREAD;

typedef struct _VMCA_DIR_SYNC_PARAMS
{
	LONG refCount;

	pthread_mutex_t  mutex;
	pthread_mutex_t* pMutex;

	DWORD   dwSyncIntervalSecs;

	time_t  lastUpdateTime;

	BOOLEAN bRefresh;

} VMCA_DIR_SYNC_PARAMS, *PVMCA_DIR_SYNC_PARAMS;

typedef struct _VMCA_SERVER_GLOBALS
{
    pthread_mutex_t    mutex;
    pthread_mutex_t    mutexCRL;
    DWORD              dwCurrentCRLNumber;

    pthread_rwlock_t   svcMutex;

    FILE* fVMCALog;

    // Security descriptor for VMCA-Service resources.
  //  PSECURITY_DESCRIPTOR_ABSOLUTE gpVMCAServSD;

    dcethread*          pRPCServerThread;
    VMCA_SERVER_STATE    vmcadState;

    PVMCA_X509_CA       pCA;
    VMCA_FUNC_LEVEL     dwFuncLevel;

    PVMCA_DIR_SYNC_PARAMS pDirSyncParams;
    PVMCA_THREAD          pDirSyncThr;

    HANDLE              gpEventLog;

} VMCA_SERVER_GLOBALS, *PVMCA_SERVER_GLOBALS;

typedef struct
_JSONKeyValue {
    char*                           key;
    char*                           val;
} JSONKeyValue;

typedef struct
_VMCARequestObj {
    PSTR                            method;
    PSTR                            uri;
    PSTR                            ver;
    PSTR                            connection;
    PSTR                            transferEncoding;
    PSTR                            contentLength;
    PSTR*                           payload;
    FILE*                           debugFile;
    JSONKeyValue*                   params;
} VMCARequestObj;

#ifdef _WIN32
typedef struct _VMCA_NTSERVICE_DATA
{
    SERVICE_STATUS_HANDLE hServiceStatus;
    HANDLE stopServiceEvent;
} VMCA_NTSERVICE_DATA, *PVMCA_NTSERVICE_DATA;

#endif // _WIN32


#ifdef __cplusplus
}
#endif
