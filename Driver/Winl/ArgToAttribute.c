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

#include "ArgToAttribute.h"
#include "ArgumentType.h"
#include "Argument.h"
#include "Message.h"
#include "Attribute.h"

static const int s_argsToAttribsDatapath[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_DATAPATH_NAME, DATAPATH)] = OVS_USPACE_DP_ATTRIBUTE_NAME,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_DATAPATH_STATS, DATAPATH)] = OVS_USPACE_DP_ATTRIBUTE_STATS,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_DATAPATH_UPCALL_PORT_ID, DATAPATH)] = OVS_USPACE_DP_ATTRIBUTE_UPCALL_PID,
};

static const int s_argsToAttribsTunnel[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_ID, PI_TUNNEL)] = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_ID,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_IPV4_SRC, PI_TUNNEL)] = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_IPV4_SRC,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_IPV4_DST, PI_TUNNEL)] = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_IPV4_DST,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_TOS, PI_TUNNEL)] = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_TOS,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_TTL, PI_TUNNEL)] = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_TTL,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_DONT_FRAGMENT, PI_TUNNEL)] = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_DONT_FRAGMENT,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_CHECKSUM, PI_TUNNEL)] = OVS_USPACE_TUNNEL_KEY_ATTRIBUTE_CSUM,
};

static const int s_argsToAttribsPI[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_PACKET_PRIORITY, PI)] = OVS_USPACE_KEY_ATTRIBUTE_PRIORITY,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_DP_INPUT_PORT, PI)] = OVS_USPACE_KEY_ATTRIBUTE_IN_PORT,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_ETH_ADDRESS, PI)] = OVS_USPACE_KEY_ATTRIBUTE_ETHERNET,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_ETH_TYPE, PI)] = OVS_USPACE_KEY_ATTRIBUTE_ETHERTYPE,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_VLAN_TCI, PI)] = OVS_USPACE_KEY_ATTRIBUTE_VLAN,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_IPV4, PI)] = OVS_USPACE_KEY_ATTRIBUTE_IPV4,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_IPV6, PI)] = OVS_USPACE_KEY_ATTRIBUTE_IPV6,

    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TCP, PI)] = OVS_USPACE_KEY_ATTRIBUTE_TCP,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_UDP, PI)] = OVS_USPACE_KEY_ATTRIBUTE_UDP,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_SCTP, PI)] = OVS_USPACE_KEY_ATTRIBUTE_SCTP,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_ICMP, PI)] = OVS_USPACE_KEY_ATTRIBUTE_ICMP,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_ICMP6, PI)] = OVS_USPACE_KEY_ATTRIBUTE_ICMPV6,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_ARP, PI)] = OVS_USPACE_KEY_ATTRIBUTE_ARP,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_NEIGHBOR_DISCOVERY, PI)] = OVS_USPACE_KEY_ATTRIBUTE_ND,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_MPLS, PI)] = OVS_USPACE_KEY_ATTRIBUTE_MPLS,

    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_PACKET_MARK, PI)] = OVS_USPACE_KEY_ATTRIBUTE_SKB_MARK,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_TUNNEL_GROUP, PI)] = OVS_USPACE_KEY_ATTRIBUTE_TUNNEL,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_MPLS, PI)] = OVS_USPACE_KEY_ATTRIBUTE_MPLS,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PI_ENCAP_GROUP, PI)] = OVS_USPACE_KEY_ATTRIBUTE_ENCAP,
};

static const int s_argsToAttribsFlow[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_STATS, FLOW)] = OVS_USPACE_FLOW_ATTRIBUTE_STATS,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_TCP_FLAGS, FLOW)] = OVS_USPACE_FLOW_ATTRIBUTE_TCP_FLAGS,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_TIME_USED, FLOW)] = OVS_USPACE_FLOW_ATTRIBUTE_USED,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_CLEAR, FLOW)] = OVS_USPACE_FLOW_ATTRIBUTE_CLEAR,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_PI_GROUP, FLOW)] = OVS_USPACE_FLOW_ATTRIBUTE_KEY,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_ACTIONS_GROUP, FLOW)] = OVS_USPACE_FLOW_ATTRIBUTE_ACTIONS,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_FLOW_MASK_GROUP, FLOW)] = OVS_USPACE_FLOW_ATTRIBUTE_MASK
};

static const int s_argsToAttribsUpcall[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_UPCALL_PORT_ID, ACTION_UPCALL)] = OVS_USPACE_UPCALL_ATTRIBUTE_PID,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_UPCALL_DATA, ACTION_UPCALL)] = OVS_USPACE_UPCALL_ATTRIBUTE_USERDATA,
};

static const int s_argsToAttribsSample[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_SAMPLE_PROBABILITY, ACTION_SAMPLE)] = OVS_USPACE_SAMPLE_ATTRIBUTE_PROBABILITY,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP, ACTION_SAMPLE)] = OVS_USPACE_SAMPLE_ATTRIBUTE_ACTIONS,
};

static const int s_argsToAttribsActions[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_OUTPUT_TO_PORT, ACTION)] = OVS_USPACE_ACTION_ATTRIBUTE_OUTPUT,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_UPCALL_GROUP, ACTION)] = OVS_USPACE_ACTION_ATTRIBUTE_USERSPACE,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_SETINFO_GROUP, ACTION)] = OVS_USPACE_ACTION_ATTRIBUTE_SET,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_PUSH_VLAN, ACTION)] = OVS_USPACE_ACTION_ATTRIBUTE_PUSH_VLAN,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_POP_VLAN, ACTION)] = OVS_USPACE_ACTION_ATTRIBUTE_POP_VLAN,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_SAMPLE_GROUP, ACTION)] = OVS_USPACE_ACTION_ATTRIBUTE_SAMPLE,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_PUSH_MPLS, ACTION)] = OVS_USPACE_ACTION_ATTRIBUTE_PUSH_MPLS,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_ACTION_POP_MPLS, ACTION)] = OVS_USPACE_ACTION_ATTRIBUTE_POP_MPLS
};

static const int s_argsToAttribsPacket[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PACKET_BUFFER, PACKET)] = OVS_USPACE_PACKET_ATTRIBUTE_PACKET,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PACKET_PI_GROUP, PACKET)] = OVS_USPACE_PACKET_ATTRIBUTE_KEY,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PACKET_ACTIONS_GROUP, PACKET)] = OVS_USPACE_PACKET_ATTRIBUTE_ACTIONS,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_PACKET_USERDATA, PACKET)] = OVS_USPACE_PACKET_ATTRIBUTE_USERDATA
};

static const int s_argsToAttribsPortOptions[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_OPTION_DESTINATION_PORT, OFPORT_OPTION)] = OVS_USPACE_TUNNEL_ATTRIBUTE_DST_PORT,
};

static const int s_argsToAttribsPort[] =
{
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_NUMBER, OFPORT)] = OVS_USPACE_VPORT_ATTRIBUTE_PORT_NO,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_NAME, OFPORT)] = OVS_USPACE_VPORT_ATTRIBUTE_NAME,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_STATS, OFPORT)] = OVS_USPACE_VPORT_ATTRIBUTE_STATS,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_TYPE, OFPORT)] = OVS_USPACE_VPORT_ATTRIBUTE_TYPE,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_UPCALL_PORT_ID, OFPORT)] = OVS_USPACE_VPORT_ATTRIBUTE_UPCALL_PID,
    [OVS_ARG_TOINDEX(OVS_ARGTYPE_OFPORT_OPTIONS_GROUP, OFPORT)] = OVS_USPACE_VPORT_ATTRIBUTE_OPTIONS,
};

typedef struct _OVS_ARG_GROUP_INFO
{
    OVS_ARGTYPE parent;
    const int* group;
    OVS_ARGTYPE min;
    OVS_ARGTYPE max;
}OVS_ARG_GROUP_INFO, *POVS_ARG_GROUP_INFO;

static const OVS_ARG_GROUP_INFO s_argsToAttribs[OVS_ARG_GROUP_COUNT] =
{
    { OVS_ARGTYPE_PSEUDOGROUP_DATAPATH, s_argsToAttribsDatapath, OVS_ARGTYPE_FIRST_DATAPATH, OVS_ARGTYPE_LAST_DATAPATH },
    { OVS_ARGTYPE_PSEUDOGROUP_FLOW, s_argsToAttribsFlow, OVS_ARGTYPE_FIRST_FLOW, OVS_ARGTYPE_LAST_FLOW },
    { OVS_ARGTYPE_PSEUDOGROUP_OFPORT, s_argsToAttribsPort, OVS_ARGTYPE_FIRST_OFPORT, OVS_ARGTYPE_LAST_OFPORT },
    { OVS_ARGTYPE_PSEUDOGROUP_PACKET, s_argsToAttribsPacket, OVS_ARGTYPE_FIRST_PACKET, OVS_ARGTYPE_LAST_PACKET },

    { OVS_ARGTYPE_FLOW_PI_GROUP, s_argsToAttribsPI, OVS_ARGTYPE_FIRST_PI, OVS_ARGTYPE_LAST_PI },
    { OVS_ARGTYPE_FLOW_MASK_GROUP, s_argsToAttribsPI, OVS_ARGTYPE_FIRST_PI, OVS_ARGTYPE_LAST_PI },
    { OVS_ARGTYPE_FLOW_ACTIONS_GROUP, s_argsToAttribsActions, OVS_ARGTYPE_FIRST_ACTION, OVS_ARGTYPE_LAST_ACTION },

    { OVS_ARGTYPE_PI_ENCAP_GROUP, s_argsToAttribsPI, OVS_ARGTYPE_FIRST_PI, OVS_ARGTYPE_LAST_PI },
    { OVS_ARGTYPE_PI_TUNNEL_GROUP, s_argsToAttribsTunnel, OVS_ARGTYPE_FIRST_PI_TUNNEL, OVS_ARGTYPE_LAST_PI_TUNNEL },

    { OVS_ARGTYPE_PACKET_PI_GROUP, s_argsToAttribsPI, OVS_ARGTYPE_FIRST_PI, OVS_ARGTYPE_LAST_PI },
    { OVS_ARGTYPE_PACKET_ACTIONS_GROUP, s_argsToAttribsActions, OVS_ARGTYPE_FIRST_ACTION, OVS_ARGTYPE_LAST_ACTION },

    { OVS_ARGTYPE_ACTION_UPCALL_GROUP, s_argsToAttribsUpcall, OVS_ARGTYPE_FIRST_ACTION_UPCALL, OVS_ARGTYPE_LAST_ACTION_UPCALL },
    { OVS_ARGTYPE_ACTION_SETINFO_GROUP, s_argsToAttribsPI, OVS_ARGTYPE_FIRST_PI, OVS_ARGTYPE_LAST_PI },
    { OVS_ARGTYPE_ACTION_SAMPLE_GROUP, s_argsToAttribsSample, OVS_ARGTYPE_FIRST_ACTION_SAMPLE, OVS_ARGTYPE_LAST_ACTION_SAMPLE },
   
    { OVS_ARGTYPE_ACTION_SAMPLE_ACTIONS_GROUP, s_argsToAttribsActions, OVS_ARGTYPE_FIRST_ACTION, OVS_ARGTYPE_LAST_ACTION },
    { OVS_ARGTYPE_OFPORT_OPTIONS_GROUP, s_argsToAttribsPortOptions, OVS_ARGTYPE_FIRST_OFPORT_OPTION, OVS_ARGTYPE_LAST_OFPORT_OPTION },
};

static const OVS_ARG_GROUP_INFO* _FindGroup(OVS_ARGTYPE parentArgType, _Out_ OVS_ARGTYPE* pMin, _Out_ OVS_ARGTYPE* pMax)
{
    for (int i = 0; i < OVS_ARG_GROUP_COUNT; ++i)
    {
        const OVS_ARG_GROUP_INFO* pGroup = s_argsToAttribs + i;

        if (parentArgType == pGroup->parent)
        {
            *pMin = pGroup->min;
            *pMax = pGroup->max;

            return pGroup;
        }
    }

    OVS_CHECK(__UNEXPECTED__);
    return NULL;
}

BOOLEAN Reply_SetAttrType(OVS_ARGTYPE parentArgType, _Inout_ OVS_ARGUMENT* pArg)
{
    const OVS_ARG_GROUP_INFO* pGroup = NULL;
    OVS_ARGTYPE minArg = OVS_ARGTYPE_INVALID, maxArg = OVS_ARGTYPE_INVALID;
    ULONG attrType = 0;

    pGroup = _FindGroup(parentArgType, &minArg, &maxArg);

    OVS_CHECK_RET(pGroup, FALSE);
    OVS_CHECK_RET(pArg->type >= minArg && pArg->type <= maxArg, FALSE);

    attrType = pGroup->group[OVS_ARG_TOINDEX(pArg->type, DATAPATH)];
    OVS_CHECK_RET(attrType <= MAXUINT16, FALSE);

    pArg->type = (UINT16)attrType;

    return TRUE;
}