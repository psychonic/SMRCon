#include "rcon.h"

#include "CDetour/detours.h"

// tier1 supremecy
#include <bitbuf.h>
#include <netadr.h>
#include <utllinkedlist.h>

typedef unsigned int listenerId_t;

struct listener_t
{
	listenerId_t	id;
	bool			authed;
	bool			hasAddr;
	netadr_t		addr;
};

class CServerRemoteAccess;

#define SERVERDATA_EXECCOMMAND 2
#define SERVERDATA_AUTH 3

static CDetour *detWriteReq;
static CDetour *detCheckPass;
static CDetour *detIsPass;
static CDetour *detSocketClosed;
static CDetour *detLogCommand;

static int iRemoteListenersOffs;
static CServerRemoteAccess *g_pServer;

static bool g_bInRConCommand = false;
static listenerId_t iLastListener;


inline listener_t GetListenerFromId(listenerId_t id)
{
	CUtlLinkedList<listener_t, listenerId_t> *m_Listeners = (CUtlLinkedList<listener_t, listenerId_t> *)((intptr_t)g_pServer + iRemoteListenersOffs);

	return m_Listeners->Element(id);
}

DETOUR_DECL_MEMBER2(LogCommand, void, listenerId_t, id, const char *, data)
{
	g_pServer = (CServerRemoteAccess *)(this);

	listener_t listener = GetListenerFromId(id);

	cell_t res;
	g_fwdOnRConLog->PushCell(id);
	g_fwdOnRConLog->PushString((listener.hasAddr) ? listener.addr.ToString(true) : "");
	g_fwdOnRConLog->PushString(data);
	g_fwdOnRConLog->Execute(&res);

	if (res == Pl_Continue)
	{
		return DETOUR_MEMBER_CALL(LogCommand)(id, data);
	}

	return;
}

DETOUR_DECL_MEMBER4(WriteDataRequest, void, void *, pRCon, listenerId_t, id, const void *, pData, int, size)
{
	g_pServer = (CServerRemoteAccess *)(this);

	listener_t listener = GetListenerFromId(id);

	// Sending commands doesn't mean that they're authed
	if (!listener.authed)
	{
		// let the engine decide their fate
		return DETOUR_MEMBER_CALL(WriteDataRequest)(pRCon, id, pData, size);
	}

	if (size < (int)((sizeof(int)*2) + sizeof(char)))
	{
		// we need to be able to read at least two ints and a string from this
		return DETOUR_MEMBER_CALL(WriteDataRequest)(pRCon, id, pData, size);
	}

	bf_read buffer(pData, size);

	/*int reqId = */ buffer.ReadLong();
	int type = buffer.ReadLong();
	if (type != SERVERDATA_EXECCOMMAND)
	{
		// Auth will go through our auth handler already and we don't care about anything else
		return DETOUR_MEMBER_CALL(WriteDataRequest)(pRCon, id, pData, size);
	}

	// Just because they're authed doesn't mean we'll let them do anything. Pass the info to sp
	char command[512];
	if (!buffer.ReadString(command, sizeof(command)-1))
	{
		return DETOUR_MEMBER_CALL(WriteDataRequest)(pRCon, id, pData, size);
	}

	command[sizeof(command)-1] = 0;
	
	cell_t allow = 1;
	cell_t res;
	g_fwdOnRConCommand->PushCell(id);
	g_fwdOnRConCommand->PushString((listener.hasAddr) ? listener.addr.ToString(true) : "");
	g_fwdOnRConCommand->PushString(command);
	g_fwdOnRConCommand->PushCellByRef(&allow);
	g_fwdOnRConCommand->Execute(&res);

	if (res == Pl_Continue || allow != 0)
	{
		g_bInRConCommand = true;
		DETOUR_MEMBER_CALL(WriteDataRequest)(pRCon, id, pData, size);
		g_bInRConCommand = false;
	}
	else
	{
		// we have to trigger logging on our own if we're not calling WriteDataRequest
		char loginfo[512];
		g_pSM->Format(loginfo, sizeof(loginfo), "command \"%s\" (rejected)", command);
		DETOUR_MEMBER_MCALL_CALLBACK(LogCommand, this)(id, loginfo);
	}
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

	bool origRet = DETOUR_MEMBER_CALL(IsPassword)(password);
	cell_t bSuccess = origRet ? 1 : 0;

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

	return (bSuccess != 0);
}

/*
 * RCon socket funcs from CRConServer vtable
 * 0	CRConServer::ShouldAcceptSocket(int,netadr_s  const&)
 * 1	CRConServer::OnSocketAccepted(int,netadr_s  const&,void **)
 * 2	CRConServer::OnSocketClosed(int,netadr_s  const&,void *)
 */

DETOUR_DECL_MEMBER3(OnSocketClosed, void, int, unk, const netadr_s&, addr, void *, pSocketData)
{
	/*
	 * From OnSocketAccepted, 2nd in vtable
	 * Win:
	 *   result = sub_1016E4B0(1, a2);
     *   *(_DWORD *)(v3 + 8) = result;
	 * Lin:
	 *   *(_DWORD *)(v4 + 8) = CServerRemoteAccess::GetNextListenerID((int)g_ServerRemoteAccess, 1, a3);
	 *
	 * 8 is our magic number for the listener id
	 */
	listenerId_t id = *(listenerId_t *)((intptr_t)pSocketData + 8);

	g_fwdOnRConDisconnect->PushCell(id);
	g_fwdOnRConDisconnect->Execute(NULL);

	return DETOUR_MEMBER_CALL(OnSocketClosed)(unk, addr, pSocketData);
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

	detSocketClosed = DETOUR_CREATE_MEMBER(OnSocketClosed, "OnSocketClosed");
	if (detSocketClosed == NULL)
	{
		g_pSM->LogError(myself, "Error setting up OnSocketClosed detour");
		return false;
	}

	detLogCommand = DETOUR_CREATE_MEMBER(LogCommand, "LogCommand");
	if (detLogCommand == NULL)
	{
		g_pSM->LogError(myself, "Error setting up LogCommand detour");
		return false;
	}

	detWriteReq->EnableDetour();
	detCheckPass->EnableDetour();
	detIsPass->EnableDetour();
	detSocketClosed->EnableDetour();
	detLogCommand->EnableDetour();

	return true;
}

#define KILL_DET(det) \
	det->DisableDetour(); \
	det = NULL;

void RemoveRConDetours()
{
	KILL_DET(detWriteReq);
	KILL_DET(detCheckPass);
	KILL_DET(detIsPass);
	KILL_DET(detSocketClosed);
	KILL_DET(detLogCommand);
}

cell_t IsCmdFromRCon(IPluginContext *pContext, const cell_t *params)
{
	return (g_bInRConCommand) ? 1 : 0;
}

sp_nativeinfo_t g_Natives[] = 
{
	{"SMRCon_IsCmdFromRCon",	IsCmdFromRCon},
	{NULL,						NULL},
};
