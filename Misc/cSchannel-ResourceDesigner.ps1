$moduleName = 'cSchannel'

$Protocol = New-xDscResourceProperty -Name Protocol -Type String -Attribute Key -ValidateSet 'Multi-Protocol Unified Hello','PCT 1.0','SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2' -Description ''
$includeClientSide = New-xDscResourceProperty -Name includeClientSide -Type Boolean -Attribute Write -Description ''
$Ensure = New-xDscResourceProperty -Name Ensure -Type String -Attribute Write -ValidateSet "Present", "Absent" -Description ''
New-xDscResource -Name cProtocol -Property @($Protocol, $includeClientSide, $Ensure) -ModuleName $moduleName -FriendlyName cProtocol

$Cipher = New-xDscResourceProperty -Name Cipher -Type String -Attribute Key -ValidateSet 'AES 128/128','AES 256/256','DES 56/56','NULL','RC2 128/128','RC2 40/128','RC2 56/128','RC4 128/128','RC4 40/128','RC4 56/128','RC4 64/128','Triple DES 168' -Description ''
$Ensure = New-xDscResourceProperty -Name Ensure -Type String -Attribute Write -ValidateSet "Present", "Absent" -Description ''
New-xDscResource -Name cCipher -Property @($Cipher, $Ensure) -ModuleName $moduleName -FriendlyName cCipher

$Hash = New-xDscResourceProperty -Name Hash -Type String -Attribute Key -ValidateSet 'MD5','SHA','SHA256','SHA384','SHA512' -Description ''
$Ensure = New-xDscResourceProperty -Name Ensure -Type String -Attribute Write -ValidateSet "Present", "Absent" -Description ''
New-xDscResource -Name cHash -Property @($Hash, $Ensure) -ModuleName $moduleName -FriendlyName cHash

$KeyExchangeAlgoritm = New-xDscResourceProperty -Name KeyExchangeAlgoritm -Type String -Attribute Key -ValidateSet 'Diffie-Hellman','ECDH','PKCS' -Description ''
$Ensure = New-xDscResourceProperty -Name Ensure -Type String -Attribute Write -ValidateSet "Present", "Absent" -Description ''
New-xDscResource -Name cKeyExchangeAlgoritm -Property @($KeyExchangeAlgoritm, $Ensure) -ModuleName $moduleName -FriendlyName cKeyExchangeAlgoritm

$CryptoCipherSuites = New-xDscResourceProperty -Name CryptoCipherSuites -Type String[] -Attribute Write -Description ''
$Ensure = New-xDscResourceProperty -Name Ensure -Type String -Attribute Key -ValidateSet "Present", "Absent" -Description ''
New-xDscResource -Name cCryptoCipherSuites -Property @($CryptoCipherSuites, $Ensure) -ModuleName $moduleName -FriendlyName CryptoCipherSuites

