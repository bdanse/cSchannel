#https://www.hass.de/content/setup-your-iis-ssl-perfect-forward-secrecy-and-tls-12
#https://support.microsoft.com/nl-nl/kb/245030

#region Helper function
function Switch-SchannelProtocol
{
    param(
        [string]$protocol,
        [ValidateSet("Server","Client")] 
        [string]$type,
        [bool]$enable
    )
    $protocalRootKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' 
    $protocalKey = $protocalRootKey + "\" + $protocol + "\" + $type
    if(-not (Test-Path -Path $protocalKey))
    {
        New-Item -Path $protocalKey -Force | Out-Null
    }

    switch ($enable)
    {
        True {$value = '0xffffffff'}
        False {$value = '0'}
    }

    New-ItemProperty -Path $protocalKey -Name 'Enabled' -Value $value -PropertyType Dword -Force | Out-Null
    New-ItemProperty -Path $protocalKey -Name 'DisabledByDefault' -Value ([int](-not $enable)) -PropertyType Dword -Force | Out-Null
}

function Test-SchannelProtocol
{
    param(
        [string]$protocol,
        [ValidateSet("Server","Client")] 
        [string]$type,
        [bool]$enable
    )
    $protocalRootKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' 
    $protocalKey = $protocalRootKey + "\" + $protocol + "\" + $type

    switch ($enable)
    {
        True {$value = '4294967295'}
        False {$value = '0'}
    }

    $result = $false
    $ErrorActionPreference = "SilentlyContinue"
    if((Get-ItemProperty -Path $protocalKey -Name Enabled) -and (Get-ItemProperty -Path $protocalKey -Name DisabledByDefault))
    {
        if ((Get-ItemPropertyValue -Path $protocalKey -Name Enabled) -eq $value -and (Get-ItemPropertyValue -Path $protocalKey -Name DisabledByDefault) -eq ([int](-not $enable)))
        {
            $result = $true
        }
    }

    return $result
}

function Enable-SchannelProtocol
{
    param(
        [ValidateSet('Multi-Protocol Unified Hello','PCT 1.0','SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2')]
        [string]$protocol,
        [ValidateSet("Server","Client")] 
        [string]$type
    )
    if(-not (Test-SchannelProtocol -protocol $protocol -type $type -enable $true))
    {
        Switch-SchannelProtocol -protocol $protocol -type $type -enable $true
    }
}

function Disable-SchannelProtocol
{
    param(
        [ValidateSet('Multi-Protocol Unified Hello','PCT 1.0','SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2')]
        [string]$protocol,
        [ValidateSet("Server","Client")] 
        [string]$type
    )
    if(-not (Test-SchannelProtocol -protocol $protocol -type $type -enable $false))
    {
        Switch-SchannelProtocol -protocol $protocol -type $type -enable $false
    }
}

function Test-SchannelItem
{
    param(
        [string]$itemKey,
        [bool]$enable
    )
    
    switch ($enable)
    {
        True {$value = '4294967295'}
        False {$value = '0'}
    }
    
    $result = $false
    $ErrorActionPreference = "SilentlyContinue"
    if(Get-ItemProperty -Path $itemKey -Name Enabled)
    { 
        if ((Get-ItemPropertyValue -Path $itemKey -Name Enabled) -eq $value)
        {
            $result = $true
        }
    }
    return $result
}

function Switch-SchannelItem
{
    param(
        [string]$itemKey,
        [bool]$enable
    )

    if(-not (Test-Path -Path $itemKey))
    {
        New-Item -Path $itemKey -Force | Out-Null
    }
    switch ($enable)
    {
        True {$value = '0xffffffff'}
        False {$value = '0'}
    }

    New-ItemProperty -Path $itemKey -Name 'Enabled' -Value $value -PropertyType Dword -Force | Out-Null
    
}

function Enable-SchannelCipher
{
    param(
        [ValidateSet('AES 128/128','AES 256/256','DES 56/56','NULL','RC2 128/128','RC2 40/128','RC2 56/128','RC4 128/128','RC4 40/128','RC4 56/128','RC4 64/128','Triple DES 168')]
        [string]$cipher
    )

    $RootKey = 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
    $Key = $RootKey + "\" + $cipher 
    Switch-SchannelItem -itemKey $Key -enable $true
  
}

function Disable-SchannelCipher
{
    param(
        [ValidateSet('AES 128/128','AES 256/256','DES 56/56','NULL','RC2 128/128','RC2 40/128','RC2 56/128','RC4 128/128','RC4 40/128','RC4 56/128','RC4 64/128','Triple DES 168')]
        [string]$cipher
    )

    $RootKey = 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
    $Key = $RootKey + "\" + $cipher 
    Switch-SchannelItem -itemKey $Key -enable $false
  
}

function Test-SchannelCipher
{
    param(
        [ValidateSet('AES 128/128','AES 256/256','DES 56/56','NULL','RC2 128/128','RC2 40/128','RC2 56/128','RC4 128/128','RC4 40/128','RC4 56/128','RC4 64/128','Triple DES 168')]
        [string]$cipher,
        [bool]$enable
    )
    $RootKey = 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
    $Key = $RootKey + "\" + $cipher 
    Test-SchannelItem -itemKey $Key -enable $enable
}

function Enable-SchannelHash
{
    param(
        [ValidateSet('MD5','SHA','SHA256','SHA384','SHA512')]
        [string]$hash
    )

    $RootKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes'
    $Key = $RootKey + "\" + $hash 
    Switch-SchannelItem -itemKey $Key -enable $true
  
}

function Disable-SchannelHash
{
    param(
        [ValidateSet('MD5','SHA','SHA256','SHA384','SHA512')]
        [string]$hash
    )

    $RootKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes'
    $Key = $RootKey + "\" + $hash 
    Switch-SchannelItem -itemKey $Key -enable $false
  
}

function Test-SchannelHash
{
    param(
        [ValidateSet('MD5','SHA','SHA256','SHA384','SHA512')]
        [string]$hash,
        [bool]$enable
    )
    $RootKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes'
    $Key = $RootKey + "\" + $hash 
    Test-SchannelItem -itemKey $Key -enable $enable
}

function Enable-SchannelKeyExchangeAlgorithm
{
    param(
        [ValidateSet('Diffie-Hellman','ECDH','PKCS')]
        [string]$algorithm
    )

    $RootKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms'
    $Key = $RootKey + "\" + $algorithm 
    Switch-SchannelItem -itemKey $Key -enable $true
  
}

function Disable-SchannelKeyExchangeAlgorithm
{
    param(
        [ValidateSet('Diffie-Hellman','ECDH','PKCS')]
        [string]$algorithm
    )

    $RootKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms'
    $Key = $RootKey + "\" + $algorithm 
    Switch-SchannelItem -itemKey $Key -enable $false
  
}

function Test-SchannelKeyExchangeAlgorithm
{
    param(
        [ValidateSet('Diffie-Hellman','ECDH','PKCS')]
        [string]$algorithm,
        [bool]$enable
    )
    $RootKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms'
    $Key = $RootKey + "\" + $algorithm 
    Test-SchannelItem -itemKey $Key -enable $enable
}
#endregion
