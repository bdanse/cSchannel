# Load the Helper Module 
Import-Module -Name "$PSScriptRoot\..\Helper.psm1" 

# Localized messages
data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData -StringData @'
        ProtocolSetServer              = Setting Server side protocol [{0}] enable {1}.
        ProtocolSetClient              = Setting Client side protocol [{0}] enable {1}.
        ProtocolTestServer             = Testing Server side protocol [{0}] enable {1}.
        ProtocolTestClient             = Testing Client side protocol [{0}] enable {1}.
        ProtocolNotCompliant           = Protocol {0} not compliant.
        ProtocolCompliant              = Protocol {0} compliant.
      
'@
}

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateSet("Multi-Protocol Unified Hello","PCT 1.0","SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2")]
        [System.String]
        $Protocol,

        [System.Boolean]
        $includeClientSide

    )

    $ChildItems = Get-ChildItem -Path "$RootKey\$Protocol"
    if($includeClientSide -eq $false -or $includeClientSide -eq $null)
    {
        $childItems = $childitems | ?{$_.PsChildName -eq "Server"} 
    }
  
    $ensure = "Absent" 

    foreach ($ChildItem in $ChildItems)
    {
 <#     
        foreach ($property in $ChildItem.Property)
        {
            $value = Get-ItemPropertyValue -Path $ChildItem.PSPath -Name $property
            if ($property -eq "Enabled" -and $value -eq '0xffffffff')
            {
                $Ensure = "Present"
            }
            
        }
#>
        $enabled = Get-ItemPropertyValue -Path $ChildItem.PSPath -Name "Enabled"
        $DisabledByDefault = Get-ItemPropertyValue -Path $ChildItem.PSPath -Name "Enabled"
        if($enabled -eq '0xffffffff' -and $DisabledByDefault -eq 0)
        {
            $Ensure = "Present"
        }
    }
    
    $returnValue = @{
    Protocol = [System.String]$Protocol
    includeClientSide = [System.Boolean]$includeClientSide
    Ensure = [System.String]$Ensure
    }

    $returnValue

}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateSet("Multi-Protocol Unified Hello","PCT 1.0","SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2")]
        [System.String]
        $Protocol,

        [System.Boolean]
        $includeClientSide,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

        if($includeClientSide -eq $true)
        {
            Write-Verbose -Message ($LocalizedData.SetClientProtocol -f $Protocol, $Ensure)
            Switch-SchannelProtocol -protocol $Protocol -type Client -enable ($Ensure -eq "Present")
        }
        Write-Verbose -Message ($LocalizedData.SetServerProtocol -f $this.Protocol, $this.Ensure)
        Switch-SchannelProtocol -protocol $Protocol -type Server -enable ($Ensure -eq "Present")

}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateSet("Multi-Protocol Unified Hello","PCT 1.0","SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2")]
        [System.String]
        $Protocol,

        [System.Boolean]
        $includeClientSide,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

        $Compliant = $true

        if($includeClientSide -eq $true)
        {
            Write-Verbose -Message ($LocalizedData.TestClientProtocol -f $Protocol, $Ensure)
            if(-not (Test-SchannelProtocol -protocol $Protocol -type Client -enable ($Ensure -eq "Present")))
            {
                $Compliant = $false
            }    
        }
        Write-Verbose -Message ($LocalizedData.TestServerProtocol -f $this.Protocol, $Ensure)
        if(-not (Test-SchannelProtocol -protocol $Protocol -type Server -enable ($Ensure -eq "Present")))
        {
            $Compliant = $false
        }
        
        if($Compliant)
        {
            Write-Verbose -Message ($LocalizedData.ProtocolCompliant -f $Protocol, $Ensure)
        }
        else
        {
            Write-Verbose -Message ($LocalizedData.ProtocolNotCompliant -f $Protocol, $this.Ensure)
        }
         
        return $Compliant
}


Export-ModuleMember -Function *-TargetResource

