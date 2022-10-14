function Get-SvcSddl {

    <#
    .SYNOPSIS
        Gets the access control list of a service in SDDL form.
    
    .DESCRIPTION
        Get-SvcSddl is a function ets the access control list of a service in SDDL form for a specific service on the machine targeted.

    .PARAMETER ComputerName
        Specifies the name of the machine to execute this script on.
    
    .PARAMETER ServiceName
        Specifies the shortname of the service.

    .EXAMPLE
        Get-SvcSddl -ComputerName 'gc-test-stjens' -ServiceName 'bits'
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
        [string]$ServiceName
    )

    ### Checking if code is running in elevated session
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    if (!($Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))){
        Throw "Script is not running as Administrator. Stopping script, no changes were made .."
    }  

    ### Getting SDDL and checking if sid has an Ace on scm as a friendly reminder
    switch ($ServiceName) {
        {@($ComputerName -ne $ENV:COMPUTERNAME)} {
                $sddl = Invoke-Command -ScriptBlock {sc.exe sdshow $using:ServiceName | Where-Object {$_}} -ComputerName $ComputerName -ErrorAction Stop
        }
        {@($ComputerName -eq $ENV:COMPUTERNAME)} {
                $sddl = sc.exe sdshow $ServiceName | Where-Object {$_} -ErrorAction Stop
        }
    }
    ### Print output
    $sddl
}
Export-ModuleMember -Function Get-SvcSddl