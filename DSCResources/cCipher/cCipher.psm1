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
        [ValidateSet("AES 128/128","AES 256/256","DES 56/56","NULL","RC2 128/128","RC2 40/128","RC2 56/128","RC4 128/128","RC4 40/128","RC4 56/128","RC4 64/128","Triple DES 168")]
        [System.String]
        $Cipher,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )
    
    $returnValue = @{
    Cipher = [System.String]$Cipher
    Ensure = [System.String](Test-SchannelCipher -cipher $Cipher -enable ($Ensure -eq "Present"))
    }

    $returnValue
    
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateSet("AES 128/128","AES 256/256","DES 56/56","NULL","RC2 128/128","RC2 40/128","RC2 56/128","RC4 128/128","RC4 40/128","RC4 56/128","RC4 64/128","Triple DES 168")]
        [System.String]
        $Cipher,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

        if($Ensure -eq "Present")
        {
            Write-Verbose -Message ($LocalizedData.ItemEnable -f 'Cipher', $Cipher)
            Enable-SchannelCipher -cipher $Cipher
        }    
        else
        {
            Write-Verbose -Message ($LocalizedData.ItemDisable -f 'Cipher', $Cipher)
            Disable-SchannelCipher -cipher $Cipher
        }


}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateSet("AES 128/128","AES 256/256","DES 56/56","NULL","RC2 128/128","RC2 40/128","RC2 56/128","RC4 128/128","RC4 40/128","RC4 56/128","RC4 64/128","Triple DES 168")]
        [System.String]
        $Cipher,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )
    
    $Compliant = $true
    Write-Verbose -Message ($LocalizedData.ItemTest -f 'Cipher', $Cipher)
    if(-not (Test-SchannelCipher -cipher $Cipher -enable ($Ensure -eq "Present")))
    {
        $Compliant = $false
    }
            
    if($Compliant)
    {
        Write-Verbose -Message ($LocalizedData.ItemCompliant -f 'Cipher', $Cipher)
    }
    else
    {
        Write-Verbose -Message ($LocalizedData.ItemNotCompliant -f 'Cipher', $Cipher)
    }
    return $Compliant
}


Export-ModuleMember -Function *-TargetResource

