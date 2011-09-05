#include <smrcon>

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
	LogToGame("rcon id %d with address %s sent command \"%s\"", rconId, address, command);
	
	return Plugin_Continue;
}