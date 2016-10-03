Configuration SslBestPractise
{
    Import-DscResource -ModuleName cSchannel -ModuleVersion 1.0

    #region settings
    $DeniedProtocols = @(
    @{Protocol='Multi-Protocol Unified Hello';Ensure='Absent'},
    @{Protocol='PCT 1.0';Ensure='Absent'},
    @{Protocol='SSL 2.0';Ensure='Absent'},
    @{Protocol='SSL 3.0';Ensure='Absent'}
    )

    $AllowedProtocols = @(
    @{Protocol='TLS 1.0';Ensure='Present'},
    @{Protocol='TLS 1.1';Ensure='Present'},
    @{Protocol='TLS 1.2';Ensure='Present'}
    )

    $DeniedCiphers = @(
    @{Cipher='DES 56/56';Ensure='Absent'},
    @{Cipher='NULL';Ensure='Absent'},
    @{Cipher='RC2 128/128';Ensure='Absent'},
    @{Cipher='RC2 40/128';Ensure='Absent'},
    @{Cipher='RC2 56/128';Ensure='Absent'},
    @{Cipher='RC4 128/128';Ensure='Absent'},
    @{Cipher='RC4 40/128';Ensure='Absent'},
    @{Cipher='RC4 56/128';Ensure='Absent'},
    @{Cipher='RC4 64/128';Ensure='Absent'}
    )

    $AllowedCiphers = @(
    @{Cipher='AES 128/128';Ensure='Present'},
    @{Cipher='AES 256/256';Ensure='Present'},
    @{Cipher='Triple DES 168';Ensure='Present'}
    )

    $AllowedHashes = @(
    @{Hash='MD5';Ensure='Present'},
    @{Hash='SHA';Ensure='Present'},
    @{Hash='SHA256';Ensure='Present'},
    @{Hash='SHA384';Ensure='Present'},
    @{Hash='SHA512';Ensure='Present'}
    )

    $AllowedKeyExchangeAlgoritm =  @(
    @{KeyExchangeAlgoritm='Diffie-Hellman';Ensure='Present'}, 
    @{KeyExchangeAlgoritm='ECDH';Ensure='Present'},
    @{KeyExchangeAlgoritm='PKCS';Ensure='Present'}
    )

    $cipherSuites = @(
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
    'TLS_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA',
    'TLS_RSA_WITH_AES_128_CBC_SHA',
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
    )
    #endregion

    node localhost{
    
        foreach($Denied in $DeniedProtocols)
        {
            cProtocol ("Deny-" + ($Denied.Protocol).replace('.','').replace(' ', ''))
            {
                Protocol = $Denied.Protocol
                Ensure = $Denied.Ensure
                includeClientSide = $true
            }
        }
        
        foreach($Allowed in $AllowedProtocols)
        {
            cProtocol ("Allow-" + ($Allowed.Protocol).replace('.','').replace(' ', ''))
            {
                Protocol = $Allowed.Protocol
                Ensure = $Allowed.Ensure
                includeClientSide = $true
            }
        }

        foreach($Denied in $DeniedCiphers)
        {
            cCipher ("Deny-" + ($Denied.Cipher).replace('.','').replace(' ', '').replace('/','-'))
            {
                Cipher = $Denied.Cipher
                Ensure = $Denied.Ensure
                
            }
        }

        foreach($Allowed in $AllowedCiphers)
        {
            cCipher ("Allow-" + ($Allowed.Cipher).replace('.','').replace(' ', '').replace('/','-'))
            {
                Cipher = $Allowed.Cipher
                Ensure = $Allowed.Ensure
                
            }
        }
        
        foreach($Allowed in $AllowedHashes)
        {
            cHash ("Allow-" + ($Allowed.Hash))
            {
                Hash = $Allowed.Hash
                Ensure = $Allowed.Ensure
                
            }
        }

        foreach($Allowed in $AllowedKeyExchangeAlgoritm)
        {
            cKeyExchangeAlgoritm ("Allow-" + ($Allowed.KeyExchangeAlgoritm))
            {
                KeyExchangeAlgoritm = $Allowed.KeyExchangeAlgoritm
                Ensure = $Allowed.Ensure
                
            }
        }
        
       cCipherSuites CipherSuites
       {
            Ensure = "Present"
            CipherSuitesOrder = $cipherSuites
       }
       
       
    }
}
SslBestPractise
Start-DscConfiguration -Path .\SslBestPractise -Wait -Verbose -Force