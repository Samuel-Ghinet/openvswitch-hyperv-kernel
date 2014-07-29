/*
Copyright 2014 Cloudbase Solutions Srl

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "OFDatapath.h"
#include "OvsCore.h"
#include "WinlDatapath.h"
#include "List.h"
#include "Argument.h"
#include "Message.h"
#include "ArgumentType.h"
#include "OFPort.h"
#include "OvsCore.h"
#include "OFFlowTable.h"

#include "Switch.h"

#include "Driver.h"

VOID Datapath_DestroyNow_Unsafe(OVS_DATAPATH* pDatapath)
{
    OVS_FLOW_TABLE* pFlowTable = NULL;
    LOCK_STATE_EX lockState;

    KFree(pDatapath->name);

    DATAPATH_LOCK_WRITE(pDatapath, &lockState);

    pFlowTable = pDatapath->pFlowTable;
    pDatapath->pFlowTable = NULL;
    OVS_REFCOUNT_DESTROY(pFlowTable);

    DATAPATH_UNLOCK(pDatapath, &lockState);

    NdisFreeRWLock(pDatapath->pRwLock);
}

OVS_DATAPATH* GetDefaultDatapath_Ref(const char* funcName)
{
    OVS_DATAPATH* pDatapath = NULL;

    DRIVER_LOCK();

    OVS_CHECK(!IsListEmpty(&g_driver.datapathList));

    pDatapath = CONTAINING_RECORD(g_driver.datapathList.Flink, OVS_DATAPATH, listEntry);
    pDatapath = RefCount_Reference(pDatapath, funcName);

    DRIVER_UNLOCK();

    return pDatapath;
}

//unsafe = does not lock datapath
static void _GetDatapathStats_Unsafe(_In_ OVS_DATAPATH* pDatapath, _Out_ OVS_DATAPATH_STATS* pStats, _Out_ OVS_DATAPATH_MEGAFLOW_STATS* pMegaFlowStats)
{
    OVS_FLOW_TABLE* pFlowTable = NULL;

    pFlowTable = pDatapath->pFlowTable;

    pMegaFlowStats->masksMatched = pDatapath->statistics.masksMatched;
    pMegaFlowStats->countMasks = FlowTable_CountMasks(pDatapath->pFlowTable);

    pStats->flowTableMatches = pDatapath->statistics.flowTableMatches;
    pStats->flowTableMissed = pDatapath->statistics.flowTableMissed;
    pStats->countLost = pDatapath->statistics.countLost;
}

OVS_ERROR CreateMsgFromDatapath(OVS_DATAPATH* pDatapath, UINT32 sequence, UINT8 cmd, _Inout_ OVS_MESSAGE* pMsg, UINT32 dpIfIndex, UINT32 pid)
{
    OVS_ARGUMENT* pNameArg = NULL, *pStatsArg = NULL, *pMFStatsArg = NULL, *pUserFeaturesArg = NULL;
    char* datapathName = NULL;
    OVS_DATAPATH_STATS dpStats = { 0 };
    OVS_DATAPATH_MEGAFLOW_STATS dpMegaFlowStats = { 0 };
    ULONG nameLen = 0;
    OVS_ERROR error = OVS_ERROR_NOERROR;
    LOCK_STATE_EX lockState;
    UINT32 userFeatures = 0;
    ULONG i = 0;

    OVS_CHECK(pMsg);

    DATAPATH_LOCK_READ(pDatapath, &lockState);

    nameLen = (ULONG)strlen(pDatapath->name) + 1;
    datapathName = KAlloc(nameLen);
    RtlCopyMemory(datapathName, pDatapath->name, nameLen);

    _GetDatapathStats_Unsafe(pDatapath, &dpStats, &dpMegaFlowStats);
    userFeatures = pDatapath->userFeatures;

    DATAPATH_UNLOCK(pDatapath, &lockState);

    CHECK_E(CreateMsg(pMsg, pid, sequence, sizeof(OVS_MESSAGE), OVS_MESSAGE_TARGET_DATAPATH, 
        cmd, dpIfIndex, 4));

    pNameArg = CreateArgumentStringA_Alloc(OVS_ARGTYPE_DATAPATH_NAME, datapathName);
    CHECK_B_E(pNameArg, OVS_ERROR_NOMEM);
    AddArgToArgGroup(pMsg->pArgGroup, pNameArg, &i);

    pStatsArg = CreateArgument_Alloc(OVS_ARGTYPE_DATAPATH_STATS, &dpStats);
    CHECK_B_E(pStatsArg, OVS_ERROR_NOMEM);
    AddArgToArgGroup(pMsg->pArgGroup, pStatsArg, &i);

    pMFStatsArg = CreateArgument_Alloc(OVS_ARGTYPE_DATAPATH_MEGAFLOW_STATS, &dpMegaFlowStats);
    CHECK_B_E(pMFStatsArg, OVS_ERROR_NOMEM);
    AddArgToArgGroup(pMsg->pArgGroup, pMFStatsArg, &i);

    pUserFeaturesArg = CreateArgument_Alloc(OVS_ARGTYPE_DATAPATH_USER_FEATURES, &userFeatures);
    CHECK_B_E(pUserFeaturesArg, OVS_ERROR_NOMEM);
    AddArgToArgGroup(pMsg->pArgGroup, pUserFeaturesArg, &i);

Cleanup:
    KFree(datapathName);

    if (error != OVS_ERROR_NOERROR)
    {
        KFree(pNameArg);
        KFree(pStatsArg);
    }
    else
    {
        DestroyArgument(pNameArg);
        DestroyArgument(pStatsArg);
        DestroyArgument(pMFStatsArg);
        DestroyArgument(pUserFeaturesArg);

        FreeGroupWithArgs(pMsg->pArgGroup);
    }

    return error;
}

BOOLEAN CreateDefaultDatapath(NET_IFINDEX dpIfIndex)
{
    OVS_DATAPATH* pDatapath = NULL;
    BOOLEAN ok = TRUE;

    pDatapath = KZAlloc(sizeof(OVS_DATAPATH));
    if (pDatapath == NULL)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pDatapath->switchIfIndex = dpIfIndex;
    pDatapath->refCount.Destroy = Datapath_DestroyNow_Unsafe;
    pDatapath->name = NULL;

    //i.e. at the beginning we don't have a datapath, we expect the userspace to tell us: 'create datapath'
    pDatapath->deleted = TRUE;

    //ALLOCATE TABLE
    pDatapath->pFlowTable = FlowTable_Create();
    if (!pDatapath->pFlowTable)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pDatapath->pRwLock = NdisAllocateRWLock(NULL);

    OVS_CHECK(!Driver_HaveDatapath());

    //TODO: use an interlocked single list instead!
    DRIVER_LOCK();
    InsertHeadList(&g_driver.datapathList, &pDatapath->listEntry);
    DRIVER_UNLOCK();

Cleanup:
    if (!ok && pDatapath)
    {
        if (pDatapath->pFlowTable)
        {
            FlowTable_DestroyNow_Unsafe(pDatapath->pFlowTable);
        }
        
        KFree(pDatapath);
    }

    return ok;
}

BOOLEAN Datapath_FlushFlows(OVS_DATAPATH* pDatapath)
{
    OVS_FLOW_TABLE* pOldTable = NULL;
    OVS_FLOW_TABLE* pNewTable = NULL;
    LOCK_STATE_EX lockState = { 0 };
    BOOLEAN ok = TRUE;

    //pDatapath contains the pFlowTable, so we must lock its rw lock, to replace the pFlowTable
    DATAPATH_LOCK_WRITE(pDatapath, &lockState);

    pOldTable = pDatapath->pFlowTable;
    pNewTable = FlowTable_Create();
    if (!pNewTable)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pDatapath->pFlowTable = pNewTable;

    OVS_REFCOUNT_DESTROY(pOldTable);

Cleanup:
    DATAPATH_UNLOCK(pDatapath, &lockState);
    return ok;
}

OVS_FLOW_TABLE* Datapath_ReferenceFlowTable(OVS_DATAPATH* pDatapath)
{
    OVS_FLOW_TABLE* pFlowTable = NULL;
    LOCK_STATE_EX lockState;

    OVS_CHECK(pDatapath);
    DATAPATH_LOCK_READ(pDatapath, &lockState);

    pFlowTable = OVS_REFCOUNT_REFERENCE(pDatapath->pFlowTable);

    DATAPATH_UNLOCK(pDatapath, &lockState);

    return pFlowTable;
}