# About
This module can be used to *get*, *add* or *remove* access control entries in access control lists for (windows) services.<br>
The functions use "sc.exe" to get and set the SDDL string. The function converts the SDDL string using the **RawAcl Class** in the **System.Security.AccessControl** namespace to create Ace's which is then added or used to match an existing Ace and remove it, using the InsertAce/RemoveAce Methods, before converting it back into a SDDL string and setting it locally or remotely on the targeted machine.
<br>

This module contains 4 functions<br>
```
Get-SvcSddl
This function, gets access control entries on a service for a specified sid in SDDL form.
```

```
Get-SvcAce
This function, gets access control entries on a service for a specified sid.
```

```
New-SvcAce
This function, sets a new access control entry on a service based on sid and accessmask.
```

```
Remove-SvcAce
This function, removes a access control entry on a service that contains the entered sid.
```

# Getting Started
How to install and use the module<br>

## How to install
This module has been uploaded to Powershell Gallery and can be installed using the following command
```powershell
Install-Module SvcAce
```

## How to use
The module can be used locally or remotely using WS-MAN. Both require that you enter a machine name.
The access mask can be entered, either in HEX or decimal, but must be supported in order to create a working access control entry.
For further information, review the documentation from Microsoft here: [[MS-DTYP]: Syntax | Microsoft Docs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070), and always remember to test new access masks, before rolling it out into production.

### Syntax
```powershell
Get-SvcSddl     -ComputerName <String> -ServiceName <String>
Get-SvcAce      -ComputerName <String> -ServiceName <String> -sid <String>
New-SvcAce      -ComputerName <String> -ServiceName <String> -sid <String> -accessMask <Int>
Remove-SvcAce   -ComputerName <String> -ServiceName <String> -sid <String> -accessMask <Int>
```

### Examples
**Example for New-SvcAce**
```powershell
New-SvcAce -ComputerName 'server1' -ServiceName 'service1' -sid 'S-1-5-18' -accessMask 0x2009D
```

**Example for Get-SvcAce**
```powershell
Get-SvcAce -ComputerName 'server1' -ServiceName 'service1' -sid 'S-1-5-18'
```

**Output**

```console
BinaryLength       : 36
AceQualifier       : AccessAllowed
IsCallback         : False
OpaqueLength       : 0
AccessMask         : 131229
SecurityIdentifier : S-1-5-18
AceType            : AccessAllowed
AceFlags           : None
IsInherited        : False
InheritanceFlags   : None
PropagationFlags   : None
AuditFlags         : None
```
*The Get-SvcAce shows you the ace(s) set on a windows service for a specific sid.*<br>
*This can be used to retrieve the accessmask, to then remove it if neccesary, or copy the value to add a new ace for another sid on the same or a different service.*

