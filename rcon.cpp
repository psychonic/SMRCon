#include "rcon.h"

#include "CDetour/detours.h"

// tier1 supremecy
#include <bitbuf.h>
#include <convar.h>
#include <netadr.h>
#include <utllinkedlist.h>

static CDetour *detWriteReq;
static CDetour *detCheckPass;
static CDetour *detIsPass;

static int iRemoteListenersOffs;

typedef unsigned int listenerId_t;
static listenerId_t iLastListener;

struct listener_t
{
	listenerId_t	id;
	bool			authed;
	bool			hasAddr;
	netadr_t		addr;
};

class CServerRemoteAccess;

static CServerRemoteAccess *g_pServer;

inline listener_t GetListenerFromId(listenerId_t id)
{
	CUtlLinkedList<listener_t, listenerId_t> *m_Listeners = (CUtlLinkedList<listener_t, listenerId_t> *)((intptr_t)g_pServer + iRemoteListenersOffs);

	return m_Listeners->Element(id);
}

#define SERVERDATA_EXECCOMMAND 2
#define SERVERDATA_AUTH 3

DETOUR_DECL_MEMBER4(WriteDataRequest, void, void *, pRCon, listenerId_t, id, const void *, pData, int, size)
{
	g_pServer = (CServerRemoteAccess *)(this);

	listener_t listener = GetListenerFromId(id);

	// shenanigans
	assert(id == listener.id);

	bf_read buffer(pData, 2048);

	/*int reqId = */ buffer.ReadLong();
	int type = buffer.ReadLong();

	switch (type)
	{
	case SERVERDATA_AUTH:
		// Auth will go through our auth handler already
		return DETOUR_MEMBER_CALL(WriteDataRequest)(pRCon, id, pData, size);
	case SERVERDATA_EXECCOMMAND:
		// we want this
		break;
	default:
		// we don't care about anything else; just drop it
		return;
	}

	// We're left with just SERVERDATA_EXECCOMMAND's now

	// Sending commands doesn't mean that they're authed
	if (!listener.authed)
	{
		// let the engine decide their fate
		return DETOUR_MEMBER_CALL(WriteDataRequest)(pRCon, id, pData, size);
	}

	// Just because they're authed doesn't mean we'll let them do anything. Pass the info to sp
	char command[512];
	buffer.ReadString(command, sizeof(command)-1);
	command[sizeof(command)-1] = 0;
	
	cell_t allow = 1;
	cell_t res;
	g_fwdOnRConCommand->PushCell(id);
	g_fwdOnRConCommand->PushString((listener.hasAddr) ? listener.addr.ToString(true) : "");
	g_fwdOnRConCommand->PushString(command);
	g_fwdOnRConCommand->PushCellByRef(&allow);
	g_fwdOnRConCommand->Execute(&res);

	// plugin decided to immolate it
	if (res > Pl_Continue && allow == 0)
		return;

	return DETOUR_MEMBER_CALL(WriteDataRequest)(pRCon, id, pData, size);
}

DETOUR_DECL_MEMBER4(CheckPassword, void, void *, pRCon, listenerId_t, id, int, reqId, const char *, password)
{
	g_pServer = (CServerRemoteAccess *)(this);
	iLastListener = id;

	// IsPassword gets called inside of here
	return DETOUR_MEMBER_CALL(CheckPassword)(pRCon, id, reqId, password);
}

DETOUR_DECL_MEMBER1(IsPassword, bool, const char *, password)
{
	listener_t listener = GetListenerFromId(iLastListener);

	cell_t bSuccess;

	cell_t res;
	g_fwdOnRConAuth->PushCell(iLastListener);
	g_fwdOnRConAuth->PushString((listener.hasAddr) ? listener.addr.ToString(true) : "");
	g_fwdOnRConAuth->PushString(password);
	g_fwdOnRConAuth->PushCellByRef(&bSuccess);
	g_fwdOnRConAuth->Execute(&res);

	if (res > Pl_Continue)
	{
		if (bSuccess == 0)
			return false;
		else
			return true;
	}

	return DETOUR_MEMBER_CALL(IsPassword)(password);
}

bool InitRConDetours()
{
	if (!g_pGameConf->GetOffset("RemoteListeners", &iRemoteListenersOffs))
	{
		g_pSM->LogError(myself, "Couldn't find RemoteListeners offset in game conf");
		return false;
	}

	detWriteReq = DETOUR_CREATE_MEMBER(WriteDataRequest, "WriteDataRequest");
	if (detWriteReq == NULL)
	{
		g_pSM->LogError(myself, "Error setting up WriteDataRequest detour");
		return false;
	}

	detCheckPass = DETOUR_CREATE_MEMBER(CheckPassword, "CheckPassword");
	if (detCheckPass == NULL)
	{
		g_pSM->LogError(myself, "Error setting up CheckPassword detour");
		return false;
	}

	detIsPass = DETOUR_CREATE_MEMBER(IsPassword, "IsPassword");
	if (detIsPass == NULL)
	{
		g_pSM->LogError(myself, "Error setting up IsPassword detour");
		return false;
	}

	detWriteReq->EnableDetour();
	detCheckPass->EnableDetour();
	detIsPass->EnableDetour();

	return true;
}

void RemoveRConDetours()
{
	detWriteReq->DisableDetour();
	detWriteReq = NULL;

	detCheckPass->DisableDetour();
	detCheckPass = NULL;

	detIsPass->DisableDetour();
	detIsPass = NULL;
}
