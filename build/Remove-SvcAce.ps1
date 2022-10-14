function Remove-SvcAce {

    <#
    .SYNOPSIS
        Configures the security descriptor string of a specified service to remove an 
        access control entry with the sid and permissions specified.
    
    .DESCRIPTION
        Remove-AccessControlEntry is a function that modifies the security descriptor string
        on a defined service, by removing an Ace for a group or user, that has access.

    .PARAMETER ComputerName
        Specifies the name of the remote server to execute this script on.
    
    .PARAMETER ServiceName
        Specifies the shortname of the service that a ACE will be removed from.

    .PARAMETER sid
        Specifies the SID of an identity, eg. user or group that the access is granted for.
        If no value is supplied, the default SID will be that of the group "Sec-T1-System-WMI-RO"
    
    .PARAMETER accessMask
        Specifies the access mask in HEX that translates into the permissions that is granted in the ACE.
        If no value is supplied, the default accessMask will be "0x2009D" which is HEX for the permissions "CCLCSWRPLORC",
        which is needed for LogicMonitor to read services.
        If scmanager is defined as ServiceName, the accessMask will be corrected to "0x2001D" as that is what is supported for scmanager.
        See more information: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070

    .EXAMPLE
        Remove-AccessControlEntry -ComputerName 'gc-test-stjens' -ServiceName 'bits'

    .EXAMPLE
        Remove-AccessControlEntry -ComputerName 'gc-test-stjens' -ServiceName 'bits' -sid 'S-1-5-21-682003330-2146849767-505966439-17195'

    .EXAMPLE
        Remove-AccessControlEntry -ComputerName 'gc-test-stjens' -ServiceName 'bits' -sid 'S-1-5-21-682003330-2146849767-505966439-17195' -accessMask 0x2009D
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
    
    ### Checking if code is running in elevated session
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    if (!($Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))){
        Throw "Script is not running as Administrator. Stopping script, no changes were made .."
    }  

    ### Creating security identifier for sid
    $sid = New-Object System.Security.Principal.SecurityIdentifier($sid)

    ### Getting SDDL and checking if sid has an Ace on scm as a friendly reminder
    switch ($ServiceName) {
        {@($ComputerName -ne $ENV:COMPUTERNAME)} {
                $sddl = Invoke-Command -ScriptBlock {sc.exe sdshow $using:ServiceName | Where-Object {$_}} -ComputerName $ComputerName -ErrorAction Stop
        }
        {@($ComputerName -eq $ENV:COMPUTERNAME)} {
                $sddl = sc.exe sdshow $ServiceName | Where-Object {$_} -ErrorAction Stop
        }
    }

    ### Converting SDDL to RawSD
    $RawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)

    ### Checking if SID has an entry and removing it
    if ($RawSD.DiscretionaryAcl.SecurityIdentifier -contains $sid){
        try {
            $i = 0
            foreach ($a in $RawSD.DiscretionaryAcl){
                if (($a.SecurityIdentifier.Value -eq $sid) -and ($a.AccessMask -eq [uint32]$AccessMask)) {
                    [int]$index = $i
                    $RawSD.DiscretionaryAcl.RemoveAce($index)
                    Write-Information -MessageData "An ACE for the SID ($sid) with the access mask $AccessMask has been removed" -InformationAction Continue
                }
                $i++
            }
        }
        catch {
            Throw "Something went wrong trying to remove existing ACE .. Stopping script, no changes was made .."
        }

        ### Converting RawSD to SDDL string
        $newSDDL = $rawSD.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)

        ### Comparing old and new SDDL string for differences"
        if (!(Compare-Object $sddl $newSDDL)) {
            Throw "The SID has an Ace, but the entered accessmask does not match the entry. Stopping script, no change was made .."
        }

        ### Setting SDDL
        switch ($ComputerName) {
            {$ComputerName -ne $ENV:COMPUTERNAME} {
                Invoke-Command -ScriptBlock {sc.exe sdset $using:ServiceName $using:newSDDL} -ComputerName $ComputerName -ErrorAction Stop
            }
            {$ComputerName -eq $ENV:COMPUTERNAME} {
                sc.exe sdset $ServiceName $newSDDL -ErrorAction Stop
            }
        }
    }
    else {
        Write-Host "The Access Control Entry does not exist on the service ""$ServiceName"", no change was made.`r`n" -ForegroundColor Green
    }       
}
Export-ModuleMember -Function Remove-SvcAce