# cSchannel
cSchannel Dsc Resource to modify SSL endpoint configuration

The **cSchannel** DSC resource configures all aspects of SCHANNEL. For quick reference of the best settings check 
(https://www.nartac.com/Products/IISCrypto)

Also Alexander Hass wrote an article and scripts to do the same:
(https://www.hass.de/content/setup-your-iis-ssl-perfect-forward-secrecy-and-tls-12)

## Resources

* **cProtocol** set protocol configuration 
* **cCipher** set Cipher configuration
* **cHash** set hashes configuration
* **cKeyExchangeAlgoritm** set KeyExchangeAlgorithms configuration
* **cCipherSuites** set cipher suites order

### cProtocol
* **Protocol**: Set configuration for any of these protocols 
	* Valid values include: {'Multi-Protocol Unified Hello'|'PCT 1.0'|'SSL 2.0'|'SSL 3.0'|'TLS 1.0'|'TLS 1.1'|'TLS 1.2'}
* **includeClientSide** : Include client schannel protocol 
	* Valid values include: {$true | $false}
* **Ensure**: Wheter the SCHANNEL procotol is allowed {Present} or denied {Absent}

### cCipher
* **Cipher**: Set configuration for any of these ciphers
	* Valid values include: {'AES 128/128'|'AES 256/256'|'DES 56/56'|'NULL'|'RC2 128/128'|'RC2 40/128'|'RC2 56/128'|'RC4 128/128'|'RC4 40/128'|'RC4 56/128'|'RC4 64/128'|'Triple DES 168'}
* **Ensure**: Wheter the SCHANNEL Cipher is allowed {Present} or denied {Absent}

### cHash
* **Hash**: Set configuration for any of these Hashes
	* Valid values include: {'MD5'|'SHA'|'SHA256'|'SHA384'|'SHA512'}
* **Ensure**: Wheter the SCHANNEL Hash is allowed {Present} or denied {Absent}

### cKeyExchangeAlgoritm
* **KeyExchangeAlgoritm**: Set configuration for any of these Key Exchange Algoritms
	* Valid values include: {'Diffie-Hellman'|'ECDH'|'PKCS'}
* **Ensure**: Wheter the SCHANNEL KeyExchangeAlgoritm is allowed {Present} or denied {Absent}

### cCipherSuites
* **CipherSuitesOrder**: Array of cipher suites.
* **Ensure**: Wheter the CryptoCipherSuites is modified {Present} or Serverdefaults. {Absent}

## Example

```powershell
configuration Sample_cSchannel
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
Sample_cSchannel 
```

