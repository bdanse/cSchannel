# Load the Helper Module 
Import-Module -Name "$PSScriptRoot\..\Helper.psm1" 

# Localized messages
data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData -StringData @'
        ProtocolNotCompliant           = Protocol {0} not compliant.
        ProtocolCompliant              = Protocol {0} compliant.
        ItemTest                       = Testing {0} {1}
        ItemEnable                     = Enabling {0} {1}
        ItemDisable                    = Disabling {0} {1}
        ItemNotCompliant               = {0} {1} not compliant.
        ItemCompliant                  = {0} {1} compliant.
       
'@
}

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."

    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."
    $itemKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
    (Get-ItemPropertyValue -Path $itemKey -Name Functions)

    
    $returnValue = @{
    CryptoCipherSuites = [System.String[]](Get-ItemPropertyValue -Path $itemKey -Name Functions)
    Ensure = [System.String]$Ensure
    }

    $returnValue
    
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [System.String[]]
        $CryptoCipherSuites,

        [parameter(Mandatory = $true)]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    if($Ensure -eq "Present")
    {
        Set-CryptoCipherSuites -cipherSuitesOrder $cipherSuites
    }
    else
    {
        Remove-CryptoCipherSuites
    }


}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.String[]]
        $CryptoCipherSuites,

        [parameter(Mandatory = $true)]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    $Compliant = $true
    if(-not (Test-CryptoCipherSuites -cipherSuitesOrder $cipherSuitesOrder) -and $Ensure -eq "Present")
    {
        $Compliant = $false
    }
    $itemKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
    if((Get-ItemPropertyValue -Path $itemKey -Name Functions) -ne $null -and $Ensure -eq "Absent")
    {
        $Compliant = $false
    }    
        
    return $Compliant
}


Export-ModuleMember -Function *-TargetResource

