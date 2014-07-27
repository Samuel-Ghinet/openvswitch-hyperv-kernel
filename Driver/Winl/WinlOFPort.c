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

#include "WinlOFPort.h"
#include "OvsCore.h"
#include "OFDatapath.h"
#include "List.h"
#include "Argument.h"
#include "Message.h"
#include "ArgumentType.h"
#include "WinlDevice.h"
#include "Winetlink.h"
#include "Vxlan.h"
#include "Gre.h"
#include "NdisFilter.h"
#include "Sctx_Nic.h"
#include "OFPort.h"
#include "Error.h"

typedef struct _OVS_WINL_PORT
{
    UINT32            number;
    OVS_OFPORT_TYPE   type;
    const char*       name;
    OVS_UPCALL_PORT_IDS    upcallPortIds;

    OVS_OFPORT_STATS  stats;

    //group type: OVS_ARGTYPE_OFPORT_GROUP
    //only available option is  OVS_ARGTYPE_PORT_OPTION_DST_PORT
    OVS_ARGUMENT_GROUP* pOptions;
}OVS_WINL_PORT, *POVS_WINL_PORT;

typedef struct _PORT_FETCH_CTXT
{
    int i;
    OVS_MESSAGE* pReplyMsg;
    UINT sequence;
    UINT dpIfIndex;
    UINT pid;
    BOOLEAN multipleUpcallPids;
}PORT_FETCH_CTXT;

/************************/

static __inline VOID _OFPort_AddStats(_Inout_ OVS_OFPORT_STATS* pDest, _In_ const  OVS_OFPORT_STATS* pSrc)
{
    pDest->bytesReceived += pSrc->bytesReceived;
    pDest->bytesSent += pSrc->bytesSent;
    pDest->droppedOnReceive += pSrc->droppedOnReceive;
    pDest->droppedOnSend += pSrc->droppedOnSend;
    pDest->errorsOnReceive += pSrc->errorsOnReceive;
    pDest->errorsOnSend += pSrc->errorsOnSend;
    pDest->packetsReceived += pSrc->packetsReceived;
    pDest->packetsSent += pSrc->packetsSent;
}

static BOOLEAN _OFPort_GroupToOptions(_In_ const OVS_ARGUMENT_GROUP* pOptionsArgs, _Inout_ OVS_TUNNELING_PORT_OPTIONS* pOptions)
{
    OVS_ARGUMENT* pArg = NULL;

    OVS_CHECK(pOptions);

    if (!pOptionsArgs)
    {
        return FALSE;
    }

    pArg = FindArgument(pOptionsArgs, OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT);
    if (pArg)
    {
        pOptions->optionsFlags |= OVS_TUNNEL_OPTIONS_HAVE_UDP_DST_PORT;
        //TODO: BE or LE?
        pOptions->udpDestPort = GET_ARG_DATA(pArg, UINT16);
    }

    return TRUE;
}

static DWORD _CountBits(DWORD value)
{
    DWORD count = 0;
    for (DWORD i = 0; i < sizeof(DWORD) * 8; i++)
    {
        DWORD bit = (value >> i);
        bit &= 1;

        count += bit;
    }

    return count;
}

static OVS_ARGUMENT_GROUP* _OFPort_OptionsToGroup(_In_ const OVS_TUNNELING_PORT_OPTIONS* pOptions)
{
    UINT16 countArgs = 0;
    BOOLEAN ok = TRUE;
    OVS_ARGUMENT_GROUP* pOptionsGroup = NULL;
    OVS_ARGUMENT* pArg = NULL;
    UINT16 i = 0;

    if (!pOptions)
    {
        return NULL;
    }

    countArgs = (UINT16)_CountBits(pOptions->optionsFlags);

    pOptionsGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    if (!pOptionsGroup)
    {
        return NULL;
    }

    AllocateArgumentsToGroup(countArgs, pOptionsGroup);

    if (pOptions->optionsFlags & OVS_TUNNEL_OPTIONS_HAVE_UDP_DST_PORT)
    {
        pArg = pOptionsGroup->args + i;

        ok = SetArgument_Alloc(pArg, OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT, &pOptions->udpDestPort);

        if (!ok)
        {
            goto Cleanup;
        }

        pOptionsGroup->groupSize += pArg->length;
        ++i;
    }

Cleanup:
    if (!ok)
    {
        DestroyArguments(pOptionsGroup->args, pOptionsGroup->count);
    }

    return pOptionsGroup;
}
/************************/

static BOOLEAN _CreateMsgFromOFPort(OVS_WINL_PORT* pPort, UINT32 sequence, UINT8 cmd, _Inout_ OVS_MESSAGE* pMsg, UINT32 dpIfIndex, UINT32 pid, BOOLEAN multipleUpcallPids)
{
    OVS_ARGUMENT* pArgPortName = NULL, *pArgPortType = NULL, *pArgPortNumber = NULL;
    OVS_ARGUMENT* pArgUpcallPid = NULL, *pArgPortSats = NULL, *pArgPortOpts = NULL;
    BOOLEAN ok = TRUE;
    UINT16 argsCount = 5;
    UINT16 argsSize = 0;

    OVS_CHECK(pMsg);

    RtlZeroMemory(pMsg, sizeof(OVS_MESSAGE));

    pMsg->length = sizeof(OVS_MESSAGE);
    pMsg->type = OVS_MESSAGE_TARGET_PORT;
    pMsg->flags = 0;
    pMsg->sequence = sequence;
    pMsg->pid = pid;

    pMsg->command = cmd;
    pMsg->version = 1;
    pMsg->reserved = 0;

    pMsg->dpIfIndex = dpIfIndex;

    //arg 1: port number
    pArgPortNumber = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_NUMBER, &pPort->number);
    if (!pArgPortNumber)
    {
        ok = FALSE;
        goto Cleanup;
    }

    argsSize += pArgPortNumber->length;

    //arg 2: port type
    pArgPortType = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_TYPE, &pPort->type);
    if (!pArgPortType)
    {
        ok = FALSE;
        goto Cleanup;
    }

    argsSize += pArgPortType->length;

    //arg 3: port name
    pArgPortName = CreateArgumentStringA_Alloc(OVS_ARGTYPE_OFPORT_NAME, pPort->name);
    if (!pArgPortName)
    {
        ok = FALSE;
        goto Cleanup;
    }

    argsSize += pArgPortName->length;

    //arg 4: port upcall pid
    if (multipleUpcallPids)
    {
        pArgUpcallPid = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID, &pPort->upcallPortIds);
    }
    else
    {
        pArgUpcallPid = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID, &pPort->upcallPortIds.ids[0]);
    }

    if (!pArgUpcallPid)
    {
        ok = FALSE;
        goto Cleanup;
    }

    argsSize += pArgUpcallPid->length;
    //arg 5: port stats
    pArgPortSats = CreateArgument_Alloc(OVS_ARGTYPE_OFPORT_STATS, &pPort->stats);
    if (!pArgPortSats)
    {
        ok = FALSE;
        goto Cleanup;
    }

    argsSize += pArgPortSats->length;

    if (pPort->pOptions)
    {
        pArgPortOpts = CreateArgumentFromGroup(OVS_ARGTYPE_OFPORT_OPTIONS_GROUP, pPort->pOptions);
        if (!pArgPortOpts)
        {
            pArgPortOpts = NULL;
            return FALSE;
        }

        argsSize += pArgPortOpts->length;

        if (pArgPortOpts)
        {
            ++argsCount;
        }
    }

    pMsg->pArgGroup = KZAlloc(sizeof(OVS_ARGUMENT_GROUP));
    if (!pMsg->pArgGroup)
    {
        goto Cleanup;
    }

    AllocateArgumentsToGroup(argsCount, pMsg->pArgGroup);
    pMsg->pArgGroup->groupSize += argsSize;

    pMsg->pArgGroup->args[0] = *pArgPortNumber;
    pMsg->pArgGroup->args[1] = *pArgPortType;
    pMsg->pArgGroup->args[2] = *pArgPortName;
    pMsg->pArgGroup->args[3] = *pArgUpcallPid;
    pMsg->pArgGroup->args[4] = *pArgPortSats;

    if (argsCount == 6)
    {
        OVS_CHECK(pArgPortOpts);
        pMsg->pArgGroup->args[5] = *pArgPortOpts;
    }

Cleanup:
    if (ok)
    {
        KFree(pArgPortNumber);
        KFree(pArgPortType);
        KFree(pArgPortName);
        KFree(pArgUpcallPid);
        KFree(pArgPortSats);
        KFree(pArgPortOpts);

        return TRUE;
    }
    else
    {
        DestroyArgument(pArgPortNumber);
        DestroyArgument(pArgPortType);
        DestroyArgument(pArgPortName);
        DestroyArgument(pArgUpcallPid);
        DestroyArgument(pArgPortSats);
        DestroyArgument(pArgPortOpts);

        FreeGroupWithArgs(pMsg->pArgGroup);

        return FALSE;
    }
}

static BOOLEAN _CreateMsgFromPersistentPort(_In_ const OVS_OFPORT* pPort, PORT_FETCH_CTXT* pContext)
{
    OVS_WINL_PORT port;
    BOOLEAN ok = TRUE;
    OVS_MESSAGE replyMsg = { 0 };

    RtlZeroMemory(&port, sizeof(OVS_WINL_PORT));
    port.number = pPort->ovsPortNumber;
    port.pOptions = _OFPort_OptionsToGroup(pPort->pOptions);
    port.type = pPort->ofPortType;
    port.name = pPort->ovsPortName;
    port.stats = pPort->stats;
    port.upcallPortIds = pPort->upcallPortIds;

    ok = _CreateMsgFromOFPort(&port, pContext->sequence, OVS_MESSAGE_COMMAND_NEW, &replyMsg, pContext->dpIfIndex, pContext->pid, pContext->multipleUpcallPids);
    if (!ok)
    {
        goto Cleanup;
    }

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    replyMsg.flags |= OVS_MESSAGE_FLAG_MULTIPART;

    *(pContext->pReplyMsg + pContext->i) = replyMsg;
Cleanup:
    //NOTE: we must NOT destroy port.pOptions: it is destroy at replyMsg.pArgGroup destruction

    return ok;
}

_Use_decl_annotations_
OVS_ERROR OFPort_New(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_DATAPATH* pDatapath = NULL;
    UINT32 portNumber = OVS_INVALID_PORT_NUMBER;
    const char* ofPortName = NULL;
    UINT32 portType = 0, upcallPortId = 0;
    OVS_ARGUMENT* pArg = NULL;
    OVS_ARGUMENT_GROUP* pOptionsGroup = NULL;
    OVS_OFPORT* pPersPort = NULL;
    OVS_MESSAGE replyMsg = { 0 };
    PORT_FETCH_CTXT context = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    LOCK_STATE_EX lockState = { 0 };
    BOOLEAN locked = FALSE;
    OVS_UPCALL_PORT_IDS upcallPids = { 0 };
    BOOLEAN multiplePidsPerOFPort = FALSE;

    //NAME: required
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NAME);
    if (!pArg)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    ofPortName = pArg->data;

    //TYPE: required
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_TYPE);
    if (!pArg)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        error = OVS_ERROR_NODEV;
        goto Cleanup;
    }

    DATAPATH_LOCK_READ(pDatapath, &lockState);
    multiplePidsPerOFPort = (pDatapath->userFeatures & OVS_DATAPATH_FEATURE_MULITPLE_PIDS_PER_VPORT) ? TRUE : FALSE;
    DATAPATH_UNLOCK(pDatapath, &lockState);

    portType = GET_ARG_DATA(pArg, UINT32);

    //UPCALL PID(S): required
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID);
    if (!pArg)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    if (multiplePidsPerOFPort)
    {
        UINT32 countPids = pArg->length / sizeof(UINT32);

        upcallPids.count = countPids;
        upcallPids.ids = KZAlloc(pArg->length);

        RtlCopyMemory(upcallPids.ids, pArg->data, pArg->length);
    }

    else
    {
        upcallPortId = GET_ARG_DATA(pArg, UINT32);
        upcallPids.count = 1;
        upcallPids.ids = KZAlloc(sizeof(UINT));
        upcallPids.ids[0] = upcallPortId;
    }

    //NOTE: name is required; number is optional
    //NUMBER: optional
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NUMBER);
    if (pArg)
    {
        UINT16 validPortNumber = 0;
        portNumber = GET_ARG_DATA(pArg, UINT32);

        if (portNumber >= OVS_MAX_PORTS)
        {
            error = OVS_ERROR_FBIG;
            goto Cleanup;
        }

        validPortNumber = (UINT16)portNumber;

        pPersPort = PersPort_Create_Ref(ofPortName, &validPortNumber, portType);
        if (!pPersPort)
        {
            //TODO: perhaps we should give more specific error value
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }
    else
    {
        OVS_CHECK(ofPortName);

        pPersPort = PersPort_Create_Ref(ofPortName, /*number*/ NULL, portType);
        if (!pPersPort)
        {
            //TODO: perhaps we should give more specific error value
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_STATS);
    if (pArg)
    {
        OVS_OFPORT_STATS* pStats = pArg->data;

        pPersPort->stats = *pStats;
    }

    context.sequence = pMsg->sequence;
    context.dpIfIndex = pDatapath->switchIfIndex;
    context.pReplyMsg = &replyMsg;
    context.pid = pMsg->pid;
    context.multipleUpcallPids = multiplePidsPerOFPort;
    context.i = 0;

    PORT_LOCK_READ(pPersPort, &lockState);
    locked = TRUE;

    pPersPort->ofPortType = portType;
    pPersPort->upcallPortIds = upcallPids;

    //OPTIONS: optional
    pOptionsGroup = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_OPTIONS_GROUP);
    if (pOptionsGroup)
    {
        if (!pPersPort->pOptions)
        {
            pPersPort->pOptions = KZAlloc(sizeof(OVS_TUNNELING_PORT_OPTIONS));
            if (!pPersPort->pOptions)
            {
                error = OVS_ERROR_INVAL;
                goto Cleanup;
            }
        }

        _OFPort_GroupToOptions(pOptionsGroup, pPersPort->pOptions);
    }

    //create OVS_MESSAGE from pPersPort
    if (!_CreateMsgFromPersistentPort(pPersPort, &context))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    //write reply message to buffer.
    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_VPORT_MCGROUP);

Cleanup:
    if (pPersPort)
    {
        if (locked)
        {
            PORT_UNLOCK(pPersPort, &lockState);
        }

        if (error != OVS_ERROR_NOERROR)
        {
            //NOTE: must be referenced when called for delete
            PersPort_Delete(pPersPort);
        }
        else
        {
            OVS_REFCOUNT_DEREFERENCE(pPersPort);
        }
    }

    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR OFPort_Set(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_OFPORT* pPersPort = NULL;
    OVS_ARGUMENT_GROUP* pOptionsGroup = NULL;
    UINT32 portType = OVS_OFPORT_TYPE_INVALID;
    OVS_MESSAGE replyMsg = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    OVS_ARGUMENT* pArg = NULL;
    LOCK_STATE_EX lockState = { 0 };
    const char* ofPortName = NULL;
    UINT32 portNumber = (UINT)-1;
    PORT_FETCH_CTXT context = { 0 };
    OVS_DATAPATH* pDatapath = NULL;
    BOOLEAN locked = FALSE;
    OVS_UPCALL_PORT_IDS upcallPids = { 0 };
    UINT32 upcallPortId = 0;
    BOOLEAN multiplePidsPerOFPort = FALSE;

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    DATAPATH_LOCK_READ(pDatapath, &lockState);
    multiplePidsPerOFPort = (pDatapath->userFeatures & OVS_DATAPATH_FEATURE_MULITPLE_PIDS_PER_VPORT) ? TRUE : FALSE;
    DATAPATH_UNLOCK(pDatapath, &lockState);

    //required: NAME or NUMBER
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NAME);
    if (pArg)
    {
        ofPortName = pArg->data;
        pPersPort = PersPort_FindByName_Ref(ofPortName);
    }
    else
    {
        pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NUMBER);
        if (pArg)
        {
            portNumber = GET_ARG_DATA(pArg, UINT32);

            if (portNumber >= OVS_MAX_PORTS)
            {
                DEBUGP(LOG_ERROR, __FUNCTION__ " invalid port number: %u!\n", portNumber);
                error = OVS_ERROR_FBIG;
                goto Cleanup;
            }

            pPersPort = PersPort_FindByNumber_Ref((UINT16)portNumber);
        }
        else
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    if (!pPersPort)
    {
        error = OVS_ERROR_NODEV;
        goto Cleanup;
    }

    //UPCALL PID(S): required
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID);
    if (pArg)
    {
        if (multiplePidsPerOFPort)
        {
            UINT32 countPids = pArg->length / sizeof(UINT32);

            upcallPids.count = countPids;
            upcallPids.ids = KZAlloc(pArg->length);

            RtlCopyMemory(upcallPids.ids, pArg->data, pArg->length);
        }

        else
        {
            if (!pArg->data)
            {
                OVS_CHECK(__UNEXPECTED__);
                error = OVS_ERROR_INVAL;
                goto Cleanup;
            }

            upcallPortId = GET_ARG_DATA(pArg, UINT32);
            upcallPids.count = 1;
            upcallPids.ids = KZAlloc(sizeof(UINT));
            upcallPids.ids[0] = upcallPortId;
        }
    }

    //TYPE: if set, must be the same as original
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_TYPE);
    if (pArg)
    {
        portType = GET_ARG_DATA(pArg, UINT32);

        if (portType != (UINT32)pPersPort->ofPortType)
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    PORT_LOCK_WRITE(pPersPort, &lockState);
    locked = TRUE;

    //OPTIONS: optional
    pOptionsGroup = FindArgumentGroup(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_OPTIONS_GROUP);
    if (pOptionsGroup)
    {
        if (!pPersPort->pOptions)
        {
            pPersPort->pOptions = KZAlloc(sizeof(OVS_TUNNELING_PORT_OPTIONS));
            if (!pPersPort->pOptions)
            {
                error = OVS_ERROR_INVAL;
                goto Cleanup;
            }
        }

        if (!_OFPort_GroupToOptions(pOptionsGroup, pPersPort->pOptions))
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    //UPCALL PORT ID: optional
    if (upcallPids.count > 0)
    {
        pPersPort->upcallPortIds = upcallPids;
    }

    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_STATS);
    if (pArg)
    {
        OVS_OFPORT_STATS* pStats = pArg->data;

        _OFPort_AddStats(&(pPersPort->stats), pStats);
    }

    context.sequence = pMsg->sequence;
    context.dpIfIndex = pDatapath->switchIfIndex;
    context.pReplyMsg = &replyMsg;
    context.pid = pMsg->pid;
    context.multipleUpcallPids = multiplePidsPerOFPort;
    context.i = 0;

    if (!_CreateMsgFromPersistentPort(pPersPort, &context))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_VPORT_MCGROUP);

Cleanup:
    if (pPersPort)
    {
        if (locked)
        {
            PORT_UNLOCK(pPersPort, &lockState);
        }

        OVS_REFCOUNT_DEREFERENCE(pPersPort);
    }

    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR OFPort_Get(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_OFPORT* pPersPort = NULL;
    OVS_ARGUMENT* pArg = NULL;
    const char* ofPortName = NULL;
    UINT32 portNumber = (UINT32)-1;
    OVS_ERROR error = OVS_ERROR_NOERROR;
    LOCK_STATE_EX lockState = { 0 };
    PORT_FETCH_CTXT context = { 0 };
    OVS_DATAPATH* pDatapath = NULL;
    BOOLEAN locked = FALSE;
    BOOLEAN multiplePidsPerOFPort = FALSE;

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    DATAPATH_LOCK_READ(pDatapath, &lockState);
    multiplePidsPerOFPort = (pDatapath->userFeatures & OVS_DATAPATH_FEATURE_MULITPLE_PIDS_PER_VPORT) ? TRUE : FALSE;
    DATAPATH_UNLOCK(pDatapath, &lockState);

    //required: NAME or NUMBER
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NAME);
    if (pArg)
    {
        ofPortName = pArg->data;
        pPersPort = PersPort_FindByName_Ref(ofPortName);
    }
    else
    {
        pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NUMBER);
        if (pArg)
        {
            portNumber = GET_ARG_DATA(pArg, UINT32);

            if (portNumber >= OVS_MAX_PORTS)
            {
                DEBUGP(LOG_ERROR, __FUNCTION__ " invalid port number: %u!\n", portNumber);
                error = OVS_ERROR_FBIG;
                goto Cleanup;
            }

            pPersPort = PersPort_FindByNumber_Ref((UINT16)portNumber);
        }
        else
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    if (!pPersPort)
    {
        error = OVS_ERROR_NODEV;
        goto Cleanup;
    }

    context.sequence = pMsg->sequence;
    context.dpIfIndex = pDatapath->switchIfIndex;
    context.pReplyMsg = &replyMsg;
    context.pid = pMsg->pid;
    context.multipleUpcallPids = multiplePidsPerOFPort;
    context.i = 0;

    PORT_LOCK_READ(pPersPort, &lockState);
    locked = TRUE;

    //create message
    if (!_CreateMsgFromPersistentPort(pPersPort, &context))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    //write message
    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_VPORT_MCGROUP);

Cleanup:
    if (pPersPort)
    {
        if (locked)
        {
            PORT_UNLOCK(pPersPort, &lockState);
        }

        OVS_REFCOUNT_DEREFERENCE(pPersPort);
    }

    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR OFPort_Delete(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE replyMsg = { 0 };
    OVS_ARGUMENT* pArg = NULL;
    const char* ofPortName = NULL;
    UINT32 portNumber = (UINT32)-1;
    OVS_DATAPATH* pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    OVS_OFPORT* pPersPort = NULL;
    PORT_FETCH_CTXT context = { 0 };
    OVS_ERROR error = OVS_ERROR_NOERROR;
    LOCK_STATE_EX lockState = { 0 };
    BOOLEAN locked = FALSE;
    BOOLEAN multiplePidsPerOFPort = FALSE;

    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    DATAPATH_LOCK_READ(pDatapath, &lockState);
    multiplePidsPerOFPort = (pDatapath->userFeatures & OVS_DATAPATH_FEATURE_MULITPLE_PIDS_PER_VPORT) ? TRUE : FALSE;
    DATAPATH_UNLOCK(pDatapath, &lockState);

    //required: NAME or NUMBER
    pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NAME);
    if (pArg)
    {
        ofPortName = pArg->data;
        pPersPort = PersPort_FindByName_Ref(ofPortName);
    }
    else
    {
        pArg = FindArgument(pMsg->pArgGroup, OVS_ARGTYPE_OFPORT_NUMBER);
        if (pArg)
        {
            portNumber = GET_ARG_DATA(pArg, UINT32);

            if (portNumber >= OVS_MAX_PORTS)
            {
                DEBUGP(LOG_ERROR, __FUNCTION__ " invalid port number: %u\n", portNumber);
                error = OVS_ERROR_FBIG;
                goto Cleanup;
            }

            pPersPort = PersPort_FindByNumber_Ref((UINT16)portNumber);
        }
        else
        {
            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }
    }

    if (!pPersPort)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    if (pPersPort->ovsPortNumber == OVS_LOCAL_PORT_NUMBER)
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    context.sequence = pMsg->sequence;
    context.dpIfIndex = pDatapath->switchIfIndex;
    context.pReplyMsg = &replyMsg;
    context.pid = pMsg->pid;
    context.multipleUpcallPids = multiplePidsPerOFPort;
    context.i = 0;

    PORT_LOCK_WRITE(pPersPort, &lockState);
    locked = TRUE;

    //create mesasge
    if (!_CreateMsgFromPersistentPort(pPersPort, &context))
    {
        error = OVS_ERROR_INVAL;
        goto Cleanup;
    }

    //write message
    OVS_CHECK(replyMsg.type == OVS_MESSAGE_TARGET_PORT);
    error = WriteMsgsToDevice((OVS_NLMSGHDR*)&replyMsg, 1, pFileObject, OVS_VPORT_MCGROUP);

Cleanup:
    if (pPersPort)
    {
        if (locked)
        {
            PORT_UNLOCK(pPersPort, &lockState);
        }

        PersPort_Delete(pPersPort);
    }

    OVS_REFCOUNT_DEREFERENCE(pDatapath);

    DestroyArgumentGroup(replyMsg.pArgGroup);

    return error;
}

_Use_decl_annotations_
OVS_ERROR OFPort_Dump(const OVS_MESSAGE* pMsg, const FILE_OBJECT* pFileObject)
{
    OVS_MESSAGE *msgs = NULL;
    int i = 0, countMsgs = 1;
    LOCK_STATE_EX lockState = { 0 };
    PORT_FETCH_CTXT context = { 0 };
    OVS_GLOBAL_FORWARD_INFO* pForwardInfo = NULL;
    OVS_DATAPATH* pDatapath;
    OVS_ERROR error = OVS_ERROR_NOERROR;
    OVS_SWITCH_INFO* pSwitchInfo = NULL;
    BOOLEAN multiplePidsPerOFPort = FALSE;

    pDatapath = GetDefaultDatapath_Ref(__FUNCTION__);
    if (!pDatapath)
    {
        return OVS_ERROR_NODEV;
    }

    DATAPATH_LOCK_READ(pDatapath, &lockState);
    multiplePidsPerOFPort = (pDatapath->userFeatures & OVS_DATAPATH_FEATURE_MULITPLE_PIDS_PER_VPORT) ? TRUE : FALSE;
    DATAPATH_UNLOCK(pDatapath, &lockState);

    pSwitchInfo = Driver_GetDefaultSwitch_Ref(__FUNCTION__);
    if (!pSwitchInfo)
    {
        return OVS_ERROR_NODEV;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.sequence = pMsg->sequence;
    context.dpIfIndex = pDatapath->switchIfIndex;
    context.pid = pMsg->pid;
    context.multipleUpcallPids = multiplePidsPerOFPort;
    context.i = 0;

    pForwardInfo = pSwitchInfo->pForwardInfo;

    FXARRAY_LOCK_READ(&pForwardInfo->persistentPortsInfo, &lockState);

    if (pForwardInfo->persistentPortsInfo.count > 0)
    {
        countMsgs += pForwardInfo->persistentPortsInfo.count;

        msgs = KAlloc(countMsgs * sizeof(OVS_MESSAGE));
        if (!msgs)
        {
            FXARRAY_UNLOCK(&pForwardInfo->persistentPortsInfo, &lockState);

            error = OVS_ERROR_INVAL;
            goto Cleanup;
        }

        RtlZeroMemory(msgs, countMsgs * sizeof(OVS_MESSAGE));
        context.pReplyMsg = msgs + i;

        OVS_FXARRAY_FOR_EACH(&pForwardInfo->persistentPortsInfo, pCurItem, 
            /*if*/ !(*_CreateMsgFromPersistentPort)((const OVS_OFPORT*)pCurItem, &context),
            error = OVS_ERROR_INVAL;
        );
    }

    FXARRAY_UNLOCK(&pForwardInfo->persistentPortsInfo, &lockState);

    if (error != OVS_ERROR_NOERROR)
    {
        goto Cleanup;
    }

    //the last is dump done, so no ports means count == 1
    if (countMsgs > 1)
    {
        msgs[countMsgs - 1].type = OVS_MESSAGE_TARGET_DUMP_DONE;
        msgs[countMsgs - 1].pArgGroup = NULL;
        msgs[countMsgs - 1].length = sizeof(OVS_MESSAGE_DONE);

        error = WriteMsgsToDevice((OVS_NLMSGHDR*)msgs, countMsgs, pFileObject, OVS_VPORT_MCGROUP);
    }
    else
    {
        OVS_MESSAGE msgDone = { 0 };

        OVS_CHECK(countMsgs == 1);

        msgDone.type = OVS_MESSAGE_TARGET_DUMP_DONE;
        msgDone.command = OVS_MESSAGE_COMMAND_NEW;
        msgDone.sequence = pMsg->sequence;
        msgDone.dpIfIndex = pDatapath->switchIfIndex;
        msgDone.flags = 0;
        msgDone.pArgGroup = NULL;
        msgDone.length = sizeof(OVS_MESSAGE_DONE);
        msgDone.pid = pMsg->pid;
        msgDone.reserved = 0;
        msgDone.version = 1;

        error = WriteMsgsToDevice((OVS_NLMSGHDR*)&msgDone, 1, pFileObject, OVS_VPORT_MCGROUP);
    }

Cleanup:
    OVS_REFCOUNT_DEREFERENCE(pDatapath);
    OVS_REFCOUNT_DEREFERENCE(pSwitchInfo);

    DestroyMessages(msgs, countMsgs);

    return error;
}