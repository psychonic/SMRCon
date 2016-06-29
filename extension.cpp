/**
 * vim: set ts=4 :
 * =============================================================================
 * SourceMod Sample Extension
 * Copyright (C) 2004-2008 AlliedModders LLC.  All rights reserved.
 * =============================================================================
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, version 3.0, as published by the
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, AlliedModders LLC gives you permission to link the
 * code of this program (as well as its derivative works) to "Half-Life 2," the
 * "Source Engine," the "SourcePawn JIT," and any Game MODs that run on software
 * by the Valve Corporation.  You must obey the GNU General Public License in
 * all respects for all other code used.  Additionally, AlliedModders LLC grants
 * this exception to all derivative works.  AlliedModders LLC defines further
 * exceptions, found in LICENSE.txt (as of this writing, version JULY-31-2007),
 * or <http://www.sourcemod.net/license.php>.
 *
 * Version: $Id$
 */

#include "extension.h"
#include "rcon.h"
#include <compat_wrappers.h>

#include "CDetour/detours.h"

SMRCon g_SMRCon;		/**< Global singleton for extension's main interface */

SMEXT_LINK(&g_SMRCon);

ICvar *icvar;
CGlobalVars *gpGlobals;
IBinTools *g_pBinTools;
IGameConfig *g_pGameConf;
IForward *g_fwdOnRConAuth;
IForward *g_fwdOnRConCommand;
IForward *g_fwdOnRConDisconnect;
IForward *g_fwdOnRConLog;

bool SMRCon::SDK_OnLoad(char *error, size_t maxlength, bool late)
{
	if (!gameconfs->LoadGameConfigFile("smrcon", &g_pGameConf, error, maxlength))
	{
		return false;
	}

	CDetourManager::Init(g_pSM->GetScriptingEngine(), g_pGameConf);

	g_fwdOnRConAuth = forwards->CreateForward("SMRCon_OnAuth", ET_Event, 4, NULL, Param_Cell, Param_String, Param_String, Param_CellByRef);
	g_fwdOnRConCommand = forwards->CreateForward("SMRCon_OnCommand", ET_Event, 4, NULL, Param_Cell, Param_String, Param_String, Param_CellByRef);
	g_fwdOnRConDisconnect = forwards->CreateForward("SMRCon_OnDisconnect", ET_Ignore, 1, NULL, Param_Cell);
	g_fwdOnRConLog = forwards->CreateForward("SMRCon_OnLog", ET_Event, 3, NULL, Param_Cell, Param_String, Param_String);

	sharesys->AddNatives(myself, g_Natives);
	sharesys->AddDependency(myself, "bintools.ext", false, true);

	sharesys->RegisterLibrary(myself, "smrcon");

	return InitRConDetours();
}

void SMRCon::SDK_OnAllLoaded()
{
	SM_GET_LATE_IFACE(BINTOOLS, g_pBinTools);
}

void SMRCon::SDK_OnUnload()
{
	gameconfs->CloseGameConfigFile(g_pGameConf);

	forwards->ReleaseForward(g_fwdOnRConAuth);
	forwards->ReleaseForward(g_fwdOnRConCommand);
	forwards->ReleaseForward(g_fwdOnRConDisconnect);
	forwards->ReleaseForward(g_fwdOnRConLog);

	RemoveRConDetours();
}

bool SMRCon::SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
	
#if !defined METAMOD_PLAPI_VERSION
	gpGlobals = ismm->pGlobals();
	GET_V_IFACE_CURRENT(engineFactory, icvar, ICvar, VENGINE_CVAR_INTERFACE_VERSION);
#else
	gpGlobals = ismm->GetCGlobals();
	GET_V_IFACE_CURRENT(GetEngineFactory, icvar, ICvar, CVAR_INTERFACE_VERSION);
#endif

#if SOURCE_ENGINE >= SE_ORANGEBOX
	g_pCVar = icvar;
#endif

	CONVAR_REGISTER(this);

	return true;
}

bool SMRCon::RegisterConCommandBase(ConCommandBase *pVar)
{
	/* Always call META_REGCVAR instead of going through the engine. */
	return META_REGCVAR(pVar);
}
