# About
This module can be used to *get*, *add* or *remove* access control entries in access control lists for (windows) services.<br>
The functions use "sc.exe" to get and set the SDDL string. The function converts the SDDL string using the **RawAcl Class** in the **System.Security.AccessControl** namespace to create Ace's which is then added or used to match an existing Ace and remove it, using the InsertAce/RemoveAce Methods, before converting it back into a SDDL string and setting in remotely on the targeted machine.
<br>

# Getting Started

## About

This module contains 4 functions<br>
```
Get-SvcAce
This function, gets access control entries on a service for a specified sid.
```

```
Get-SvcSddl
This function, gets access control entries on a service for a specified sid in SDDL form.
```

```
New-SvcAce
This function, sets a new access control entry on a service based on sid and accessmask.
```

```
Remove-SvcAce
This function, removes a access control entry on a service that contains the entered sid.
```
<br>

## How to install
Download the repo, and import the module using the "Import-Module" cmdlet.
```
Import-Module .\build\SvcAce.psd1 -Force
```

<br>

## How to use

**Syntax**
```
New-SvcAce -ComputerName <String> -ServiceName <String> -sid <String> -accessMask <Int>
```

**Example for New-SvcAce**
```
New-SvcAce -ComputerName 'gc-test-stjens' -ServiceName 'bits' -sid 'S-1-5-21-682003330-2146849767-505966439-17195' -accessMask 0x2009D


[SC] SetServiceObjectSecurity SUCCESS
```

**Example for Get-SvcAce**
```
Get-SvcAce -ComputerName 'gc-test-stjens' -ServiceName 'bits' -sid 'S-1-5-21-682003330-2146849767-505966439-17195'


BinaryLength       : 36
AceQualifier       : AccessAllowed
IsCallback         : False
OpaqueLength       : 0
AccessMask         : 131229
SecurityIdentifier : S-1-5-21-682003330-2146849767-505966439-17195
AceType            : AccessAllowed
AceFlags           : None
IsInherited        : False
InheritanceFlags   : None
PropagationFlags   : None
AuditFlags         : None
```
<br>

