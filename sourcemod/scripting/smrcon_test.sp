#include <smrcon>

public OnPluginStart()
{
	RegServerCmd("rcon_echotest", rcon_echotest);
	RegConsoleCmd("rcon_echotest2", rcon_echotest2);
}

public Action:rcon_echotest(argc)
{
	decl String:arrrrg[512];
	GetCmdArgString(arrrrg, sizeof(arrrrg));
	
	PrintToServer("PTS: %s (from rcon: %s)", arrrrg, SMRCon_IsCmdFromRCon() ? "yes" : "no");
	
	return Plugin_Handled;
}

public Action:rcon_echotest2(client, argc)
{
	if (client != 0)
		return Plugin_Continue;
	
	decl String:arrrrg[512];
	GetCmdArgString(arrrrg, sizeof(arrrrg));
	
	PrintToServer("PTS: %s (from rcon: %s)", arrrrg, SMRCon_IsCmdFromRCon() ? "yes" : "no");
	
	return Plugin_Handled;
}

public Action:SMRCon_OnAuth(rconId, const String:address[], const String:password[], &bool:allow)
{
	LogToGame("rcon id %d with address %s sent password \"%s\"", rconId, address, password);
	if (!strcmp(password, "pickle"))
	{
		allow = true;
		return Plugin_Changed;
	}
	
	return Plugin_Continue;
}

public Action:SMRCon_OnCommand(rconId, const String:address[], const String:command[], &bool:allow)
{
	if (!strcmp(command, "blockthis"))
	{
		allow = false;
		return Plugin_Changed;
	}
	
	LogToGame("rcon id %d with address %s sent command \"%s\"", rconId, address, command);
	
	return Plugin_Continue;
}

public SMRCon_OnDisconnect(rconId)
{
	LogToGame("Session with rconId %d disconnected", rconId);
}

public Action:SMRCon_OnLog(rconId, const String:address[], const String:logdata[])
{
	PrintToServer("***  rcon log from %s - \"%s\"", address, logdata);
	return Plugin_Continue;
}
