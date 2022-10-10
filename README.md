# About
The functions in this module, can be used to *get*, *add* or *remove* access control entries in access control lists for (windows) services.
<br>
<br>

**Syntax**
```
Get-SvcAce -ComputerName <String> -ServiceName <String> -accessMask <Int> -sid <String>
```
<br>
<br>

# Getting Started


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