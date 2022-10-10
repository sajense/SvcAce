function New-AccessControlEntry {

    <#
    .SYNOPSIS
        Configure the security descriptor string of a specified service to add an 
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
            if (Test-WSMan -ComputerName $_ -ErrorAction SilentlyContinue) {
                $true
            }
            else {
                $false
                throw "Can't connect to remote computer $_ .."
            }
        })]
        [string]$ComputerName,
        [Parameter(
            Position=1,
            Mandatory=$true
        )]
        [ValidateScript({
            if (($_ -eq (Invoke-Command -ComputerName $ComputerName -ScriptBlock{Get-Service -Name $using:_ -ErrorAction SilentlyContinue})) -or ($_ -eq "scmanager")){
                $true
            }
            else {
                $false
                throw "$_ is not a valid service name. Try using the ""Get-Service"" cmdlet to get the correct shortname of the service."
            }
        })]
        [string]$ServiceName,
        [Parameter(
            Position=2,
            Mandatory=$false
        )]
        [ValidateScript({
            $SDDL_Aliases = @(
            "DA","DG","DU","ED","DD","DC","BA","BG","BU","LA","LG","AO","BO","PO","SO","AU","PS","CO","CG","SY","PU","WD","RE","IU","NU","SU","RC",
            "WR","AN","SA","CA","RS","EA","PA","RU","LS","NS","RD","NO","MU","LU","IS","CY","OW","ER","RO","CD","AC","RA","ES","MS","UD","HA","CN",
            "AA","RM","LW","ME","MP","HI","SI"
            )
            if ($SDDL_Aliases -contains $_) {
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
        [int]$accessMask = 0x2009D
    )

    Write-Verbose "Checking if session is running with administrative privileges .."
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    if (!($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))){
        Write-Error "Script is not running as Administrator. Stopping script, no changes were made .."
        break;
    }  

    if ($ServiceName -eq "scmanager") {
        Write-Warning "accessMask must be 0x2001D for $ServiceName .. Correcting the variable .."
        [int]$accessMask = 0x2001D
    }

    if ($ServiceName -ne "scmanager") {
        Write-Verbose "Checking if SID is present on service control manager .."
        try {
            $sc_sddl = Invoke-Command -ScriptBlock {sc.exe sdshow scmanager | Where-Object {$_}} -ComputerName $ComputerName -ErrorAction SilentlyContinue
            $sc_rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor($sc_sddl) -ErrorAction SilentlyContinue
            if ($sc_rawSD.DiscretionaryAcl.SecurityIdentifier.Value -notcontains $sid) {
                Write-Warning "The defined SID is not present on the service control manager (scmanager). LogicMonitor will not be able to monitor any services without access to scmanager .."
            }
        }
        catch {
            continue;
        }
    }

    Write-Verbose "Setting SID variable .."
    $sid = New-Object System.Security.Principal.SecurityIdentifier($sid)

    Write-Verbose "Fetching SDDL string for the service $ServiceName .."
    try {
        $sddl = Invoke-Command -ScriptBlock {sc.exe sdshow $using:ServiceName | Where-Object {$_}} -ComputerName $ComputerName
    }
    catch {
        Write-Error "Can't fetch SDDL string for the service $ServiceName .."
        break;
    }

    Write-Verbose "Converting SDDL string to raw security descriptor .."
    $rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)

    Write-Verbose "Creating ACE based on SID and access mask .."
    $ace = New-Object System.Security.AccessControl.CommonAce([System.Security.AccessControl.AceFlags]::None,[System.Security.AccessControl.AceQualifier]::AccessAllowed,$accessMask,$sid,$false,$null)

    Write-Verbose "Checking if raw security descriptor already contains ACE .."
    if ($rawSD.DiscretionaryAcl.GetEnumerator() -notcontains $ace){
       
        Write-Verbose "Raw security descriptor does not contain ACE .. Adding ACE to raw security descriptor .."
        $rawSD.DiscretionaryAcl.InsertAce($rawSD.DiscretionaryAcl.Count,$ace)

        Write-Verbose "Converting raw security descriptor to SDDL string .."
        $newSDDL = $rawSD.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)

        Write-Host "`r`nOld SDDL: `r`n$($sddl)`r`n`nNew SDDL:`r`n$($newSDDL)`r`n" -ForegroundColor White

        Write-Verbose "Commiting new SDDL string! .."
        try {
            Invoke-Command -ScriptBlock {sc.exe sdset $using:ServiceName $using:newSDDL} -ComputerName $ComputerName
        }
        catch {
            Write-Error "Something went wrong trying to set the new SDDL string on remote computer $ComputerName .. Manually check the remote computer using the 'sc.exe sdshow $Servicename'"
            break;
        }
    }
    else {
        Write-Host "The Access Control Entry already exist on the service ""$ServiceName"", no change was made.`r`n" -ForegroundColor Green
    }
}
Export-ModuleMember -Function New-AccessControlEntry