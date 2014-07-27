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

#include "OFPort.h"
#include "Sctx_Nic.h"
#include "Sctx_Port.h"
#include "List.h"
#include <ntstrsafe.h>

extern OVS_SWITCH_INFO* g_pSwitchInfo;

static LIST_ENTRY g_grePorts;
static LIST_ENTRY g_vxlanPorts;

NDIS_RW_LOCK_EX* g_pLogicalPortsLock = NULL;

/******************************** LOGICAL PORTS & TUNNELS /********************************/

static BOOLEAN _AddPersPort_Logical(LIST_ENTRY* pList, _In_ const OVS_OFPORT* pPort)
{
    OVS_LOGICAL_PORT_ENTRY* pPortEntry = NULL;
    LOCK_STATE_EX lockState = { 0 };

    pPortEntry = KAlloc(sizeof(OVS_LOGICAL_PORT_ENTRY));
    if (!pPortEntry)
    {
        return FALSE;
    }

    pPortEntry->pPort = (OVS_OFPORT*)pPort;

    NdisAcquireRWLockWrite(g_pLogicalPortsLock, &lockState, 0);
    InsertTailList(pList, &pPortEntry->listEntry);
    NdisReleaseRWLock(g_pLogicalPortsLock, &lockState);

    return TRUE;
}

static BOOLEAN _RemovePersPort_Logical(LIST_ENTRY* pList, _In_ const OVS_OFPORT* pPort)
{
    OVS_LOGICAL_PORT_ENTRY* pPortEntry = NULL;
    BOOLEAN ok = FALSE;
    LOCK_STATE_EX lockState = { 0 };

    NdisAcquireRWLockWrite(g_pLogicalPortsLock, &lockState, 0);

    OVS_LIST_FOR_EACH(OVS_LOGICAL_PORT_ENTRY, pPortEntry, pList)
    {
        if (pPortEntry->pPort == pPort)
        {
            RemoveEntryList(&pPortEntry->listEntry);

            KFree(pPortEntry);
            ok = TRUE;
            goto Cleanup;
        }
    }

Cleanup:
    NdisReleaseRWLock(g_pLogicalPortsLock, &lockState);
    return ok;
}

static BOOLEAN _AddPersPort_Gre(_In_ const OVS_OFPORT* pPort)
{
    return _AddPersPort_Logical(&g_grePorts, pPort);
}

static BOOLEAN _AddPersPort_Vxlan(_In_ const OVS_OFPORT* pPort)
{
    return _AddPersPort_Logical(&g_vxlanPorts, pPort);
}

static BOOLEAN _RemovePersPort_Gre(_In_ const OVS_OFPORT* pPort)
{
    return _RemovePersPort_Logical(&g_grePorts, pPort);
}

static BOOLEAN _RemovePersPort_Vxlan(_In_ const OVS_OFPORT* pPort)
{
    return _RemovePersPort_Logical(&g_vxlanPorts, pPort);
}

static OVS_OFPORT* _PersPort_FindTunnel_Ref(_In_ const LIST_ENTRY* pList, _In_ const OVS_TUNNELING_PORT_OPTIONS* pTunnelOptions)
{
    OVS_LOGICAL_PORT_ENTRY* pPortEntry = NULL;
    OVS_OFPORT* pOutPort = NULL;
    LOCK_STATE_EX lockState = { 0 };

    if (pList == &g_vxlanPorts)
    {
        OVS_CHECK(pTunnelOptions);
    }

    NdisAcquireRWLockRead(g_pLogicalPortsLock, &lockState, 0);

    OVS_LIST_FOR_EACH(OVS_LOGICAL_PORT_ENTRY, pPortEntry, pList)
    {
        if (pList == &g_grePorts)
        {
            pPortEntry = CONTAINING_RECORD(pList->Flink, OVS_LOGICAL_PORT_ENTRY, listEntry);
            pOutPort = OVS_REFCOUNT_REFERENCE(pPortEntry->pPort);
            goto Cleanup;
        }
        else
        {
            //VXLAN
            OVS_TUNNELING_PORT_OPTIONS* pOptions = NULL;

            OVS_CHECK(pList == &g_vxlanPorts);

            pOptions = pPortEntry->pPort->pOptions;
            OVS_CHECK(pOptions);
            OVS_CHECK(pTunnelOptions->optionsFlags & OVS_TUNNEL_OPTIONS_HAVE_UDP_DST_PORT);

            if (pOptions->udpDestPort == pTunnelOptions->udpDestPort)
            {
                pOutPort = OVS_REFCOUNT_REFERENCE(pPortEntry->pPort);
                goto Cleanup;
            }
        }
    }

Cleanup:
    NdisReleaseRWLock(g_pLogicalPortsLock, &lockState);

    return pOutPort;
}

//TODO: use PersPort_FindVxlan_Ref instead
_Use_decl_annotations_
OVS_OFPORT* PersPort_FindVxlanByDestPort_Ref(LE16 udpDestPort)
{
    OVS_LOGICAL_PORT_ENTRY* pPortEntry = NULL;

    OVS_LIST_FOR_EACH(OVS_LOGICAL_PORT_ENTRY, pPortEntry, &g_vxlanPorts)
    {
        OVS_TUNNELING_PORT_OPTIONS* pOptions = NULL;

        pOptions = pPortEntry->pPort->pOptions;
        OVS_CHECK(pOptions);

        if (pOptions->udpDestPort == udpDestPort)
        {
            return OVS_REFCOUNT_REFERENCE(pPortEntry->pPort);
        }
    }

    return NULL;
}

_Use_decl_annotations_
OVS_OFPORT* PersPort_FindGre_Ref(const OVS_TUNNELING_PORT_OPTIONS* pTunnelInfo)
{
    return _PersPort_FindTunnel_Ref(&g_grePorts, pTunnelInfo);
}

_Use_decl_annotations_
OVS_OFPORT* PersPort_FindVxlan_Ref(const OVS_TUNNELING_PORT_OPTIONS* pTunnelInfo)
{
    return _PersPort_FindTunnel_Ref(&g_vxlanPorts, pTunnelInfo);
}

/******************************** INIT AND UNINIT ********************************/

BOOLEAN PersPort_Initialize()
{
    InitializeListHead(&g_grePorts);
    InitializeListHead(&g_vxlanPorts);

    g_pLogicalPortsLock = NdisAllocateRWLock(NULL);

    return TRUE;
}

VOID PersPort_Uninitialize()
{
    OVS_CHECK(g_pLogicalPortsLock);

    NdisFreeRWLock(g_pLogicalPortsLock);
    g_pLogicalPortsLock = NULL;
}

/******************************** UTILITTY FUNCS ********************************/

static BOOLEAN _PortFriendlyNameIs(int i, const char* portName, _In_ const OVS_PORT_LIST_ENTRY* pPortEntry)
{
    char asciiPortName[IF_MAX_STRING_SIZE + 1];

    UNREFERENCED_PARAMETER(i);

    if (strlen(portName) != pPortEntry->portFriendlyName.Length / 2)
    {
        return FALSE;
    }

    OVS_CHECK(pPortEntry->portFriendlyName.Length / 2 <= IF_MAX_STRING_SIZE);

    NdisZeroMemory(asciiPortName, IF_MAX_STRING_SIZE + 1);
    WcharArrayToAscii(asciiPortName, pPortEntry->portFriendlyName.String, pPortEntry->portFriendlyName.Length / 2);

    return (0 == strcmp(portName, asciiPortName));
}

//Unsafe = does not lock PersPort
static VOID _PersPort_SetNicAndPort_Unsafe(OVS_GLOBAL_FORWARD_INFO* pForwardInfo, OVS_OFPORT* pPort)
{
    LOCK_STATE_EX lockState = { 0 };
    const char* externalPortName = "external";

    OVS_CHECK(pPort);

    //care must be taken: we lock here pForwardInfo for read, while having locked pers ports for write.
    //we must not lock in any other part pForwardInfo before or after pers ports, or we will get into a deadlock.
    FWDINFO_LOCK_READ(pForwardInfo, &lockState);

    if (pPort->ofPortType == OVS_OFPORT_TYPE_MANAG_OS)
    {
        if (pForwardInfo->pInternalPort)
        {
            pPort->portId = pForwardInfo->pInternalPort->portId;
            //TODO: should we use interlocked assign for OVS_PORT_LIST_ENTRY's port id?
            pForwardInfo->pInternalPort->ovsPortNumber = pPort->ovsPortNumber;
        }
        else
        {
            pPort->portId = NDIS_SWITCH_DEFAULT_PORT_ID;
        }
    }
    else if (pPort->ofPortType == OVS_OFPORT_TYPE_GRE)
    {
        pPort->portId = NDIS_SWITCH_DEFAULT_PORT_ID;
    }
    else if (pPort->ofPortType == OVS_OFPORT_TYPE_VXLAN)
    {
        pPort->portId = NDIS_SWITCH_DEFAULT_PORT_ID;
    }
    else if (0 == strcmp(pPort->ovsPortName, externalPortName))
    {
        if (pForwardInfo->pExternalPort)
        {
            //TODO: should we use interlockd assign for OVS_PORT_LIST_ENTRY's port id?
            pPort->portId = pForwardInfo->pExternalPort->portId;
            pPort->isExternal = TRUE;
            pForwardInfo->pExternalPort->ovsPortNumber = pPort->ovsPortNumber;
        }
        else
        {
            pPort->portId = NDIS_SWITCH_DEFAULT_PORT_ID;
        }
    }
    else
    {
        OVS_PORT_LIST_ENTRY* pPortEntry = NULL;

        pPortEntry = Sctx_FindPortBy_Unsafe(pForwardInfo, pPort->ovsPortName, _PortFriendlyNameIs);

        if (pPortEntry)
        {
            OVS_NIC_LIST_ENTRY* pNicEntry = NULL;
            pPort->portId = pPortEntry->portId;

            pNicEntry = Sctx_FindNicByPortId_Unsafe(pForwardInfo, pPortEntry->portId);
            if (pNicEntry)
            {
                pNicEntry->ovsPortNumber = pPort->ovsPortNumber;
            }
        }
    }

    FWDINFO_UNLOCK(pForwardInfo, &lockState);
}

OVS_OFPORT* PersPort_Create_Ref(_In_opt_ const char* portName, _In_opt_ const UINT16* pPortNumber, OVS_OFPORT_TYPE portType)
{
    BOOLEAN ok = TRUE;
    OVS_OFPORT* pPort = NULL;
    OVS_FIXED_SIZED_ARRAY* pPortsArray = NULL;
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = NULL;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;
    BOOLEAN locked = FALSE;
    LOCK_STATE_EX lockState;

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pForwardInfo = pSwitchInfo->pForwardInfo;
    OVS_CHECK(pForwardInfo);

    pPortsArray = &pSwitchInfo->pForwardInfo->persistentPortsInfo;

    FXARRAY_LOCK_WRITE(pPortsArray, &lockState);
    locked = TRUE;

    if (pPortsArray->count >= OVS_MAX_PORTS)
    {
        ok = FALSE;
        goto Cleanup;
    }

    if (portType == OVS_OFPORT_TYPE_MANAG_OS)
    {
        //i.e. the first internal port is port LOCAL, must be created or must have been created
        //on slot = 0 (LOCAL port's number). ovs 1.11 allows multiple internal (i.e. datapath) ports.
        OVS_CHECK(pPortsArray->firstFree == OVS_LOCAL_PORT_NUMBER ||
            pPortsArray->array[OVS_LOCAL_PORT_NUMBER]);
        OVS_CHECK(portName);
    }

    pPort = KZAlloc(sizeof(OVS_OFPORT));
    if (!pPort)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pPort->refCount.Destroy = PersPort_DestroyNow_Unsafe;
    pPort->pRwLock = NdisAllocateRWLock(NULL);

    //if name for port was not provided, we must have been given a number
    if (!portName)
    {
        if (!pPortNumber)
        {
            ok = FALSE;
            goto Cleanup;
        }

        pPort->ovsPortName = KAlloc(257);
        if (!pPort->ovsPortName)
        {
            ok = FALSE;
            goto Cleanup;
        }

        RtlStringCchPrintfA((char*)pPort->ovsPortName, 257, "kport_%u", *pPortNumber);
    }

    //if a name has been given, we use it
    else
    {
        ULONG portNameLen = (ULONG)strlen(portName) + 1;

        pPort->ovsPortName = KAlloc(portNameLen);
        if (!pPort->ovsPortName)
        {
            ok = FALSE;
            goto Cleanup;
        }

        RtlStringCchCopyA((char*)pPort->ovsPortName, portNameLen, portName);
    }

    //if port number was not given, we set it now to 0 an call below _PersPort_AddByName_Unsafe
    pPort->ovsPortNumber = (pPortNumber ? *pPortNumber : 0);
    pPort->ofPortType = portType;

    pPort = OVS_REFCOUNT_REFERENCE(pPort);

    if (portType == OVS_OFPORT_TYPE_GRE)
    {
        if (IsListEmpty(&g_grePorts))
        {
            _AddPersPort_Gre(pPort);
        }
        else
        {
            DEBUGP(LOG_ERROR, "we already have gre vport!\n");
            ok = FALSE;//TODO: return EEXISTS!
            goto Cleanup;
        }
    }
    else if (portType == OVS_OFPORT_TYPE_VXLAN)
    {
        _AddPersPort_Vxlan(pPort);
    }

    //NOTE: we may have more persistent ports than NICS: logical ports don't have nics associated
    //the same goes with hyper-v switch ports

    _PersPort_SetNicAndPort_Unsafe(pForwardInfo, pPort);

    if (pPortNumber)
    {
        OVS_ERROR error = FXArray_AddByNumber_Unsafe(pPortsArray, (OVS_FXARRAY_ITEM*)pPort, pPort->ovsPortNumber);

        if (error == OVS_ERROR_EXIST)
        {
            const OVS_OFPORT* pOtherPort = (OVS_OFPORT*)pPortsArray->array[pPort->ovsPortNumber];

            UNREFERENCED_PARAMETER(pOtherPort);

            OVS_CHECK(pOtherPort->ofPortType == pPort->ofPortType);
            OVS_CHECK(pOtherPort->ovsPortNumber == pPort->ovsPortNumber);

            ok = (error == OVS_ERROR_NOERROR);
        }

    }
    else
    {
        ok = FXArray_Add_Unsafe(pPortsArray, (OVS_FXARRAY_ITEM*)pPort, &(pPort->ovsPortNumber));
    }

    if (!ok)
    {
        goto Cleanup;
    }

Cleanup:
    if (!ok)
    {
        if (pPort)
        {
            PersPort_DestroyNow_Unsafe(pPort);
        }
    }

    if (locked)
    {
        FXARRAY_UNLOCK(pPortsArray, &lockState);
    }

    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);

    return (ok ? pPort : NULL);
}

/******************************** FIND FUNCTIONS ********************************/

static __inline BOOLEAN _PersPort_IsExternal(OVS_FXARRAY_ITEM* pItem, UINT_PTR data)
{
    OVS_OFPORT* pCurPort = (OVS_OFPORT*)pItem;

    UNREFERENCED_PARAMETER(data);

    return pCurPort->isExternal == TRUE && pCurPort->portId != NDIS_SWITCH_DEFAULT_PORT_ID;
}

_Use_decl_annotations_
OVS_OFPORT* PersPort_FindExternal_Ref()
{
    OVS_FIXED_SIZED_ARRAY* pPortsArray = NULL;
    OVS_OFPORT* pOutPort = NULL;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        goto Cleanup;
    }

    OVS_CHECK(pSwitchInfo->pForwardInfo);

    pPortsArray = &pSwitchInfo->pForwardInfo->persistentPortsInfo;

    pOutPort = (OVS_OFPORT*)FXArray_Find_Ref(pPortsArray, _PersPort_IsExternal, NULL);

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);

    return pOutPort;
}

static __inline BOOLEAN _PersPort_IsInternal(OVS_FXARRAY_ITEM* pItem, UINT_PTR data)
{
    OVS_OFPORT* pCurPort = (OVS_OFPORT*)pItem;

    UNREFERENCED_PARAMETER(data);

    return (pCurPort->ofPortType == OVS_OFPORT_TYPE_MANAG_OS && 
        pCurPort->portId != NDIS_SWITCH_DEFAULT_PORT_ID);
}

_Use_decl_annotations_
OVS_OFPORT* PersPort_FindInternal_Ref()
{
    OVS_FIXED_SIZED_ARRAY* pPortsArray = NULL;
    OVS_OFPORT* pOutPort = NULL;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        goto Cleanup;
    }

    pPortsArray = &pSwitchInfo->pForwardInfo->persistentPortsInfo;

    pOutPort = (OVS_OFPORT*)FXArray_Find_Ref(pPortsArray, _PersPort_IsInternal, NULL);

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);

    return pOutPort;
}

static __inline BOOLEAN _PersPort_NameEquals(OVS_FXARRAY_ITEM* pItem, UINT_PTR data)
{
    OVS_OFPORT* pCurPort = (OVS_OFPORT*)pItem;
    const char* ofPortName = (const char*)data;

    return (0 == strcmp(pCurPort->ovsPortName, ofPortName));
}

OVS_OFPORT* PersPort_FindByName_Ref(const char* ofPortName)
{
    OVS_FIXED_SIZED_ARRAY* pPortsArray = NULL;
    BOOLEAN ok = TRUE;
    OVS_OFPORT* pOutPort = NULL;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pPortsArray = &pSwitchInfo->pForwardInfo->persistentPortsInfo;

    pOutPort = (OVS_OFPORT*)FXArray_Find_Ref(pPortsArray, _PersPort_NameEquals, ofPortName);

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);

    return pOutPort;
}

static __inline BOOLEAN _PersPort_PortIdEquals(OVS_FXARRAY_ITEM* pItem, UINT_PTR data)
{
    OVS_OFPORT* pCurPort = (OVS_OFPORT*)pItem;
    NDIS_SWITCH_PORT_ID portId = (NDIS_SWITCH_PORT_ID)data;

    return (pCurPort->portId == portId);
}

OVS_OFPORT* PersPort_FindById_Ref(NDIS_SWITCH_PORT_ID portId)
{
    OVS_FIXED_SIZED_ARRAY* pPortsArray = NULL;
    BOOLEAN ok = TRUE;
    OVS_OFPORT* pOutPort = NULL;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pPortsArray = &pSwitchInfo->pForwardInfo->persistentPortsInfo;

    pOutPort = (OVS_OFPORT*)FXArray_Find_Ref(pPortsArray, _PersPort_PortIdEquals, &portId);

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);

    return pOutPort;
}

OVS_OFPORT* PersPort_FindById_Unsafe(NDIS_SWITCH_PORT_ID portId)
{
    OVS_FIXED_SIZED_ARRAY* pPortsArray = NULL;
    BOOLEAN ok = TRUE;
    OVS_OFPORT* pOutPort = NULL;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pPortsArray = &pSwitchInfo->pForwardInfo->persistentPortsInfo;

    pOutPort = (OVS_OFPORT*)FXArray_Find_Unsafe(pPortsArray, _PersPort_PortIdEquals, &portId);

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);

    return pOutPort;
}

static __inline BOOLEAN _PersPort_PortNumberEquals(OVS_FXARRAY_ITEM* pItem, UINT_PTR data)
{
    OVS_OFPORT* pCurPort = (OVS_OFPORT*)pItem;
    UINT16 portNumber = (UINT16)data;

    return (pCurPort->ovsPortNumber == portNumber);
}

OVS_OFPORT* PersPort_FindByNumber_Ref(UINT16 portNumber)
{
    OVS_FIXED_SIZED_ARRAY* pPortsArray = NULL;
    OVS_OFPORT* pOutPort = NULL;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;
    BOOLEAN ok = TRUE;

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        ok = FALSE;
        goto Cleanup;
    }

    pPortsArray = &pSwitchInfo->pForwardInfo->persistentPortsInfo;

    pOutPort = (OVS_OFPORT*)FXArray_Find_Ref(pPortsArray, _PersPort_PortNumberEquals, &portNumber);

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);

    return pOutPort;
}

/******************************** DELETE FUNCTIONS ********************************/

//TODO: if it comes here unreferenced, then it means it might have been deleted, I think
BOOLEAN PersPort_Delete(OVS_OFPORT* pPort)
{
    OVS_FIXED_SIZED_ARRAY* pPortsArray = NULL;
    BOOLEAN ok = TRUE;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;
    BOOLEAN portsLocked = FALSE;
    LOCK_STATE_EX lockState = { 0 };

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        ok = FALSE;
        goto Cleanup;
    }

    OVS_CHECK(pSwitchInfo->pForwardInfo);

    pPortsArray = &pSwitchInfo->pForwardInfo->persistentPortsInfo;

    FXARRAY_LOCK_WRITE(pPortsArray, &lockState);
    portsLocked = TRUE;

    if (pPort->ofPortType == OVS_OFPORT_TYPE_GRE)
    {
        _RemovePersPort_Gre(pPort);
    }
    else if (pPort->ofPortType == OVS_OFPORT_TYPE_VXLAN)
    {
        _RemovePersPort_Vxlan(pPort);
    }

    ok = FXArray_Remove_Unsafe(pPortsArray, (OVS_FXARRAY_ITEM*)pPort, pPort->ovsPortNumber);
    if (!ok)
    {
        goto Cleanup;
    }

    OVS_REFCOUNT_DEREF_AND_DESTROY(pPort);

Cleanup:
    if (portsLocked)
    {
        FXARRAY_UNLOCK(pPortsArray, &lockState);
    }

    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);

    return ok;
}

VOID PersPort_DestroyNow_Unsafe(OVS_OFPORT* pPort)
{
    KFree(pPort->ovsPortName);

    /* previously, we 'unset' the nic and port: the hyper-v switch ports & nics were set to have pPort = NULL
    ** Now we use numbers instead. Anyway, there's no need to do unset now, because:
    ** o) the only reason we keep the mapping between ovs port numbers and hyper-v switch port ids is because we need to find a port id, given an ovs port number (or ovs port name)
    ** o) we need to be able to find a persistent port, when knowing a port id, only when setting a hyper-v switch port name.
    ** o) any packet is sent out using an ovs port number (persistent port)
    ** o) it never happens for a port (hyper-v switch port or ovs port) to be created with the same number as one that had been deleted.
    */

    KFree(pPort->pOptions);

    if (pPort->pRwLock)
    {
        NdisFreeRWLock(pPort->pRwLock);
    }

    KFree(pPort);
}