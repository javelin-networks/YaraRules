rule Ransom_Destroyers
	{
	meta:
		description = "Ransomware HDD Destroyers Wipers"
	strings:
		$a = /vssadmin(.exe){0,1} delete shadows/ nocase wide
		$b = /bcdedit(.exe){0,1} [\/,-]set\s/ nocase wide
		$c = /wbadmin(.exe){0,1} delete catalog/ nocase wide
		$d = /wmic(.exe){0,1} shadowcopy delete/ nocase wide
		$b1 = "recoveryenabled no" wide nocase
		$a1 = "delete shadows /all /quiet" fullword wide
		$x3 = "delete catalog -quiet" fullword wide
		
	condition:
		any of them 
}

rule LogCleanerWevtutil
	{
	meta:
		author = "Eyal Neemany"
		description = "There was attempt to clear the event log"
	strings:
		$S1 = /wevtutil(.exe){0,1} (cl|clear-log) (Security|Setup|System|Application)/ wide nocase	
	condition:
		$S1
}