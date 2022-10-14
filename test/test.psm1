function test {

    <#
    .SYNOPSIS
        Configures the security descriptor string of a specified service to add an 
        access control entry with the permissions specified.
    
    .DESCRIPTION
        New-AccessControlEntry is a function that modifies the security descriptor string
        on a defined service, by adding an ACE that grants a group or user, access as specified
        in order to allow monitoring of services in LogicMonitor.

    .PARAMETER ComputerName
        Specifies the name of the remote server to execute this script on.
    
    .PARAMETER ServiceName
        Specifies the shortname of the service that will be configured with a new ACE entry for
        the sid and accessMask defined.

    .PARAMETER sid
        Specifies the SID of an identity, eg. user or group that the access will be granted to.
        If no value is supplied, the default SID will be that of the group "Sec-T1-System-WMI-RO"
    
    .PARAMETER accessMask
        Specifies the access mask in HEX that translates into the permissions that are granted in the ACE.
        If no value is supplied, the default accessMask will be "0x2009D" which is HEX for the permissions "CCLCSWRPLORC",
        which is needed for LogicMonitor to read services.
        If scmanager is defined as ServiceName, the accessMask will be corrected to "0x2001D" as that is what is supported for scmanager.
        See more information: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070

    .EXAMPLE
        New-AccessControlEntry -ServiceName 'bits'

    .EXAMPLE
        New-AccessControlEntry -ComputerName 'gc-test-stjens' -ServiceName 'bits'

    .EXAMPLE
        New-AccessControlEntry -ComputerName 'gc-test-stjens' -ServiceName 'bits' -sid 'S-1-5-21-682003330-2146849767-505966439-17195'

    .EXAMPLE
        New-AccessControlEntry -ComputerName 'gc-test-stjens' -ServiceName 'bits' -sid 'S-1-5-21-682003330-2146849767-505966439-17195' -accessMask 0x2009D
    #>

    [CmdletBinding()]
    param (
        [Parameter(
            Position=0,
            Mandatory=$true
        )]
        [ValidateScript({
            switch ($_) {
                {$_ -eq $ENV:COMPUTERNAME}{
                    $true
                }
                {$_ -ne $ENV:COMPUTERNAME} {
                    if (Test-WSMan -ComputerName $_ -ErrorAction SilentlyContinue) {
                        $true
                    }
                    else {
                        $false
                        throw "Can't connect to remote computer $_ .."
                    }
                }
            }
        })]
        [string]$ComputerName,
        [Parameter(
            Position=1,
            Mandatory=$true
        )]
        [ValidateScript({
            switch ($_) {
                {$_ -eq 'scmanager'}{
                    $true
                    break
                }
                {$ComputerName -eq $ENV:COMPUTERNAME} {
                    if ($_ -eq (Get-Service -Name $_ -ErrorAction SilentlyContinue).Name) {
                        $true
                    }
                    else {
                        $false
                        throw "$_ is not a valid service name. Try using the ""Get-Service"" cmdlet to get the correct shortname of the service."
                    }
                }
                {$ComputerName -ne $ENV:COMPUTERNAME} {
                    if ($_ -eq (Invoke-Command -ComputerName $ComputerName -ScriptBlock{Get-Service -Name $using:_ -ErrorAction SilentlyContinue})){
                        $true
                    }
                    else {
                        $false
                        throw "$_ is not a valid service name. Try using the ""Get-Service"" cmdlet to get the correct shortname of the service."
                    }
                }
                
            }
        })]
        [string]$ServiceName,
        [Parameter(
            Position=2,
            Mandatory=$false
        )]
        [ValidateScript({
            $SidTokens = @(
            "DA","DG","DU","ED","DD","DC","BA","BG","BU","LA","LG","AO","BO","PO","SO","AU","PS","CO","CG","SY","PU","WD","RE","IU","NU","SU","RC",
            "WR","AN","SA","CA","RS","EA","PA","RU","LS","NS","RD","NO","MU","LU","IS","CY","OW","ER","RO","CD","AC","RA","ES","MS","UD","HA","CN",
            "AA","RM","LW","ME","MP","HI","SI"
            )
            if ($SidTokens -contains $_) {
                $false
                throw "$_ is a sid-token. An abbreviated form of a well-known SID, and not allowed to be modified using this script .."
            }
            else {
                $true
            }
        })]
        [ValidateNotNullOrEmpty()]
        [string]$sid = 'S-1-5-21-682003330-2146849767-505966439-17195',
        [Parameter(
            Position=3,
            Mandatory=$false
        )]
        [ValidateNotNullOrEmpty()]
        [int]$AccessMask = 0x2009D
    )

    Write-Verbose "Fetching SDDL string for the service $ServiceName .."
    switch ($ServiceName) {
        {@($ComputerName -ne $ENV:COMPUTERNAME) -and ($_ -ne "scmanager")} {
                $scmSDDL = Invoke-Command -ScriptBlock {sc.exe sdshow scmanager | Where-Object {$_}} -ComputerName $ComputerName -ErrorAction Stop
                $sddl = Invoke-Command -ScriptBlock {sc.exe sdshow $using:ServiceName | Where-Object {$_}} -ComputerName $ComputerName -ErrorAction Stop
        }
        {@($ComputerName -eq $ENV:COMPUTERNAME) -and ($_ -ne "scmanager")} {
                $scmSDDL = sc.exe sdshow scmanager | Where-Object {$_} -ErrorAction Stop
                $sddl = sc.exe sdshow $ServiceName | Where-Object {$_} -ErrorAction Stop
        }
        {@($ComputerName -ne $ENV:COMPUTERNAME) -and ($_ -eq "scmanager")} {
                $sddl = Invoke-Command -ScriptBlock {sc.exe sdshow scmanager | Where-Object {$_}} -ComputerName $ComputerName -ErrorAction Stop
        }
        {@($ComputerName -eq $ENV:COMPUTERNAME) -and ($_ -eq "scmanager")} {
                $sddl = sc.exe sdshow scmanager | Where-Object {$_} -ErrorAction Stop
        }
    }
    if (($null -ne $scmSDDL) -and (($scmSDDL | Out-String) -notlike "*OpenService FAILED*")) {
        $sc_rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor($scmSDDL) -ErrorAction SilentlyContinue
        if ($sc_rawSD.DiscretionaryAcl.SecurityIdentifier.Value -notcontains $sid) {
            Write-Warning "The defined SID is not present on the service control manager (scmanager). LogicMonitor will not be able to monitor any services without access to scmanager .."
        }
    }

    $sddl
}