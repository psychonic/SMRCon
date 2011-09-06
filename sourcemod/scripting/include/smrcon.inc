#if defined _smrcon_included
 #endinput
#endif
#define _smrcon_included


forward Action:SMRCon_OnAuth(rconId, const String:address[], const String:password[], &bool:allow);

forward Action:SMRCon_OnCommand(rconId, const String:address[], const String:command[], &bool:allow);

forward SMRCon_OnDisconnect(rconId);

native bool:SMRCon_IsCmdFromRCon();

/** Do Not Edit Below This Line **/

public Extension:__ext_smrcon =
{
	name = "smrcon",
	file = "smrcon.ext",
#if defined AUTOLOAD_EXTENSIONS
	autoload = 1,
#else
	autoload = 0,
#endif
#if defined REQUIRE_EXTENSIONS
	required = 1,
#else
	required = 0,
#endif
};

#if !defined REQUIRE_EXTENSIONS
public __ext_smrcon_SetNTVOptional()
{
	MarkNativeAsOptional("SMRCon_IsCmdFromRCon");
}
#endif
