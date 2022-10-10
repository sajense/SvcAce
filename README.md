# About
This module can be used to *get*, *add* or *remove* access control entries in access control lists for (windows) services.<br>
The functions use "sc.exe" to get and set the SDDL string. The function converts the SDDL string using the **RawAcl Class** in the **System.Security.AccessControl** namespace to create Ace's which is then added or used to match an existing Ace and remove it, using the InsertAce/RemoveAce Methods, before converting it back into a SDDL string and setting in remotely on the targeted machine.
<br>
<br>



# Getting Started
## Prerequisites
These functions require remote connection to target machines<br>
<br>

**Syntax**
```
Get-SvcAce -ComputerName <String> -ServiceName <String> -accessMask <Int> -sid <String>
```

**Example**
```
New-SvcAce -ComputerName 'gc-test-stjens' -ServiceName 'bits' -accessMask 0x2009D -sid 'S-1-5-21-682003330-2146849767-505966439-17195'
```

**Output**
```
Old SDDL:
D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;SAFA;WDWO;;;BA)

New SDDL:
D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPLORC;;;S-1-5-21-682003330-2146849767-505966439-17195)S:(AU;SAFA;WDWO;;;BA)

[SC] SetServiceObjectSecurity SUCCESS
```