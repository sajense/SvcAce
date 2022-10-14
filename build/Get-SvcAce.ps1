function Get-SvcAce {

    <#
    .SYNOPSIS
        Get all access control entries for a service that contains the entered sid.
    
    .DESCRIPTION
        Get-SvcAce is a function that gets the access control entry for the entered service, that contains the entered sid.

    .PARAMETER ComputerName
        Specifies the name of the machine to execute this script on.
    
    .PARAMETER ServiceName
        Specifies the shortname of the service that will be configured with a new Ace for
        the sid and accessmask.

    .PARAMETER sid
        Specifies the SID of an identity, eg. user or group that has an Ace on the service.
    
    .EXAMPLE
        Get-SvcAce -ComputerName 'gc-test-stjens' -ServiceName 'bits'

    .EXAMPLE
        Get-SvcAce -ComputerName 'gc-test-stjens' -ServiceName 'bits' -sid 'S-1-5-21-682003330-2146849767-505966439-17195'
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
        [string]$sid = 'S-1-5-21-682003330-2146849767-505966439-17195'
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

    ### Checking if SID has an entry
    if ($RawSD.DiscretionaryAcl.SecurityIdentifier -contains $sid){
        foreach ($a in $RawSD.DiscretionaryAcl){
            if ($a.SecurityIdentifier.Value -eq $sid) {
                $a
            }
        }
    }    
}
Export-ModuleMember -Function Get-SvcAce