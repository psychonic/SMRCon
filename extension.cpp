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

#include "CDetour/detours.h"

SMRCon g_SMRCon;		/**< Global singleton for extension's main interface */

SMEXT_LINK(&g_SMRCon);

IGameConfig *g_pGameConf;
IForward *g_fwdOnRConAuth;
IForward *g_fwdOnRConCommand;

bool SMRCon::SDK_OnLoad(char *error, size_t maxlength, bool late)
{
	if (!gameconfs->LoadGameConfigFile("smrcon", &g_pGameConf, error, maxlength))
	{
		return false;
	}

	CDetourManager::Init(g_pSM->GetScriptingEngine(), g_pGameConf);

	g_fwdOnRConAuth = forwards->CreateForward("SMRCon_OnAuth", ET_Event, 4, NULL, Param_Cell, Param_String, Param_String, Param_CellByRef);
	g_fwdOnRConCommand = forwards->CreateForward("SMRCon_OnCommand", ET_Event, 4, NULL, Param_Cell, Param_String, Param_String, Param_CellByRef);

	plsys->AddPluginsListener(this);

	return true;
}

void SMRCon::SDK_OnUnload()
{
	gameconfs->CloseGameConfigFile(g_pGameConf);

	plsys->RemovePluginsListener(this);

	forwards->ReleaseForward(g_fwdOnRConAuth);
	forwards->ReleaseForward(g_fwdOnRConCommand);
}

void SMRCon::OnPluginLoaded(IPlugin *plugin)
{
	if (!m_bRConDetoursEnabled &&
		(g_fwdOnRConAuth->GetFunctionCount() > 0 || g_fwdOnRConCommand->GetFunctionCount() > 0))
	{
		m_bRConDetoursEnabled = InitRConDetours();
	}
}

void SMRCon::OnPluginUnloaded(IPlugin *plugin)
{
	if (m_bRConDetoursEnabled &&
		g_fwdOnRConAuth->GetFunctionCount() == 0 && g_fwdOnRConCommand->GetFunctionCount() == 0)
	{
		RemoveRConDetours();
		m_bRConDetoursEnabled = false;

	}
}
