###################################
## POWERSHELL CREDENTIAL MANAGER ##
## Written By: Nathan Ziehnert   ##
## Version: 1.0                  ##
## Website: https://z-nerd.com   ##
###################################
<#
.SYNOPSIS 
A PowerShell module to somewhat securely store and retrieve passwords and usernames in SQL.

.DESCRIPTION
A PowerShell module to store and retrieve passwords and usernames in a SQL database using certificates to encrypt 
usernames and passwords which you wish to reuse across computers and don't want to store in cleartext or manually 
encrypt for each device that uses them.

.EXAMPLE
Load this as a module for whatever script you wish to call it from.

PS> Import-Module -Name X:\Path\To\PSCredentialManager.psm1

.NOTES
This script should not be considered the most secure method to store and retrieve passwords. Any time you store
encrypted data which can be reversed, there is an inherient security risk. These passwords are only as secure as
the certificate you use to encrypt them - and specifically the private key that is used to decrypt the data. It
would be recommended for you to keep a copy of the certificate with the exportable private key separate from the
machines that the certificate is instaled on. When installing a certificate on the machine, don't allow the 
private key to be exported. If at all possible, only install the certificate for the user who will be consuming 
the password (i.e. don't install the certificate in the machine account unless the script is running as SYSTEM.)

Copyright 2018 Nathan Ziehnert

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
documentation files (the "Software"), to deal in the Software without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and 
to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO 
THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

.LINK
http://z-nerd.com/
#>
#Requires -version 4
Function New-PSCredCertificate()
{
    <#
    .SYNOPSIS
    Creates a new self-signed certificate for encrypting and decrypting credentials.
    
    .DESCRIPTION
    Creates a new self-signed certificate for encrypting and decrypting credentials.
    Requires PowerShell v4 or greater.
    
    .PARAMETER subject
    Subject name on the certificate. By default the value is 'CN=PSCredMgr'
    
    .PARAMETER friendlyName
    Friendly name on the certificate. By default the value is 'PowerShell Credential Manager'
    
    .PARAMETER validityPeriod
    The number of years you would like the certificate to remain valid. The default is 5 years.
    
    .EXAMPLE
    PS> New-PSCredCertificate -subject "CN=TotallyNotPasswordCertificate" -friendlyName "My Certificate" -validityPeriod 100
    #>
    #Requires -Version 4
    Param
    (
        [# Subject name on the certificate
        Parameter(Mandatory=$false,
        HelpMessage="Enter a subject name - by default we use 'CN=PSCredMgr'.")]
        [string]
        $subject="CN=PSCredMgr",        

        [# Friendly name on the certificate
        Parameter(Mandatory=$false,
        HelpMessage="Enter a friendly name - by default we use 'PowerShell Credential Manager'.")]
        [string]
        $friendlyName="PowerShell Credential Manager",    
        
        [# Validity period on the certificate in years
        Parameter(Mandatory=$false,
        HelpMessage="Enter the number of years you'd like for the certificate to remain valid.")]
        [Int32]
        $validityPeriod=5
    )

    try
    {
        # Create a certificate using SHA256 and a key length of 2048.
        # Maybe we can expand this a bit in the future to allow that
        # to be configured via parameters.
        $certificate = New-SelfSignedCertificate -Subject "$subject" -KeyUsage DataEncipherment -KeySpec KeyExchange -FriendlyName "$friendlyName" -NotAfter $([datetime]::now.AddYears($validityPeriod)) -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -HashAlgorithm SHA256 -KeyLength 2048 
    }
    catch
    {
        Write-Output "There was an error generating your certificate. The error was: `n$($_.Exception.Message)"
        return
    }
    Write-Output "Your certificate has been created. It is in $ENV:USERNAME's personal certificate store.`nYou'll need to import the certificate with the private key onto any device you want to`ndecrypt stored credentials from.`
                  `nThe certificate thumbrint is: $($certificate.Thumbprint)."
}

Function Get-PSCredCertificate()
{
    <#
    .SYNOPSIS
    Finds a certificate by thumbprint.
    
    .DESCRIPTION
    Finds a certificate by thumbprint and then returns that certificate object.
    
    .PARAMETER CertThumbprint
    A string with the thumbprint of the certificate. No spaces or colons - if added they will be stripped.

    .PARAMETER PublicOnly
    A switch to find a certificate even if it does not have the private key attached (to encrypt only).
    
    .EXAMPLE
    PS> Get-PSCredCertificate "1234567890ABCDEF1234567890ABCDEF12345678"
    #>
    Param
    (
        [# Certificate Thumbprint
        Parameter(Mandatory=$true,
        HelpMessage="Enter the certificate thumbprint.")]
        [string]
        $CertThumbprint,
        
        # PublicOnly
        [Parameter(Mandatory=$false)]
        [switch]
        $PublicOnly
    )
    # Replace spaces and colons just in case they were added 
    $CertThumbprint = $CertThumbprint.Replace(":","").Replace(" ","")
    
    # Find the certificate with the matching thumbprint that has a private key
    $cert = $null # clear the variable... just in case it's already set
    if($PublicOnly){ $cert = Get-ChildItem Cert:\ -Recurse | Where-Object { $_.Thumbprint -eq $CertThumbprint } | Select-Object -First 1 }
    else { $cert = Get-ChildItem Cert:\ -Recurse | Where-Object {($_.Thumbprint -eq $CertThumbprint) -and ($_.HasPrivateKey)} | Select-Object -First 1 }
    if($cert -ne $null)
    {
        return $cert
    }
    else
    {
        if($PublicOnly){ Write-Host "No certificate with thumbprint '$($CertThumbprint)' was found." }
        else{ Write-Host "No certificate with thumbprint '$($CertThumbprint)' and a private key was found." }
    }
}

Function New-PSCredSQLConnection()
{
    <#
    .SYNOPSIS
    Stores the parameters to connect to the SQL server for credentials.
    
    .DESCRIPTION
    This function sets variables needed for later consumption by the application.
    This is useful if you want to store or get many credentials, however is not
    necessary if you just pass the SQL server and database when running one of the
    module functions.
    
    .PARAMETER sqlServer
    The fully qualified domain name (or just NetBIOS name... I don't care) of the
    server which stores your credential database.
    
    .PARAMETER sqlDatabase
    The name of the database where the data is stored. By default this is "PSCM"

    .EXAMPLE
    PS> New-PSCredSQLConnection -sqlServer "SQL01.contoso.com" -sqlDatabase "Credentials"
    #>
    Param
    (
        [# SQL Server FQDN
        Parameter(Mandatory=$true,
        HelpMessage="Enter the fully qualified domain name of the SQL server you will connect to.")]
        [string]
        $sqlServer,

        [# SQL Server Database
        Parameter(Mandatory=$false,
        HelpMessage="Enter the name of the database you'll be connecting to.")]
        [string]
        $sqlDatabase="PSCM"
    )

    # Set the variables... that's really all we're doing here...
    # we need them for later consumption.
    $script:PSCredServer = $sqlServer;
    $script:PSCredDatabase = $sqlDatabase;
}

Function New-PSCredCredential()
{
    <#
    .SYNOPSIS
    Adds an encrypted password, username, and certificate thumbprint to the database.
    
    .DESCRIPTION
    Takes an input of a certificate thumbprint, cleartext password, cleartext username,
    and a unique credential purpose (e.g. "Local Administrator Credentials for Denver"),
    encrypts the password and username with the given certificate, and then dumps them 
    all into a row in the SQL database.
    
    .PARAMETER sqlServer
    The name of the SQL server you want to connect to. This can also be automatically 
    populated by running the New-PSCredSQLConnection command.
    
    .PARAMETER sqlDatabase
    The name of the SQL database you want to connect to. This can also be automatically 
    populated by running the New-PSCredSQLConnection command.
    
    .PARAMETER CredentialPurpose
    A unique name that describes the purpose of the credentials - or you can use any name
    you want, just know that you'll need it to get the credentials at a later time.
    
    .PARAMETER Username
    A username string that you wish to encrypt - this is not required.
    
    .PARAMETER Password
    A password string that you wish to encrypt.
    
    .PARAMETER CertificateThumbprint
    The certificate thumbprint which will be used to encrypt the username and password.
    
    .EXAMPLE
    PS> New-PSCredCredentials -CredentialPurpose "SQL SA Account on SQL01" -Password "ThisIsASuperSecurePassword"

    .EXAMPLE
    PS> New-PSCredCredentials -CredentialPurpose "Local Admin Account on SQL01" -Username "Administrator" -Password "ThisIsASuperSecurePassword"
    #>
    Param
    (
        # SQL Server FQDN
        [Parameter(Mandatory=$false,
        HelpMessage="Enter the fully qualified domain name of the SQL server you will connect to.")]
        [string]
        $sqlServer=$script:PSCredServer,

        # SQL Server Database
        [Parameter(Mandatory=$false,
        HelpMessage="Enter the name of the database you'll be connecting to.")]
        [string]
        $sqlDatabase=$script:PSCredDatabase,
        
        # The purpose of the credentials - this name must be unique and can be up to 256 characters.
        [Parameter(Mandatory=$true,
        HelpMessage="Enter the purpose of the credentials - this name must be unique and can be up to 256 characters.")]
        [string]
        $CredentialPurpose,

        # The username for the credentials
        [Parameter(Mandatory=$false,
        HelpMessage="Enter the username for the credentials.")]
        [string]
        $Username,        

        # The password for the credentials
        [Parameter(Mandatory=$true,
        HelpMessage="Enter the password for the credentials.")]
        [string]
        $Password, 

        # The certificate thumbprint used to encrypt
        [Parameter(Mandatory=$true,
        HelpMessage="Enter the certificate thumbprint.")]
        [string]
        $CertificateThumbprint
    )
    # Get the certificate
    $cert = $null
    $cert = Get-PSCredCertificate "$CertificateThumbprint" -PublicOnly
    if($Cert -eq $null)
    {
        Write-Output "Unable to find the certificate with the thumbprint '$($CertificateThumbprint)'."
        return
    }

    # Encrypt the password
    $EncryptedBytes = $Cert.PublicKey.Key.Encrypt([system.text.encoding]::UTF8.GetBytes($Password), $true)
    $Password = $null #clear the cleartext password
    $EncryptedPwd = [System.Convert]::ToBase64String($EncryptedBytes)

    if($Username -ne "")
    {
        # Encrypt the username
        $EncryptedBytes = $Cert.PublicKey.Key.Encrypt([system.text.encoding]::UTF8.GetBytes($Username), $true)
        $Username = $null #clear the cleartext username
        $EncryptedUser = [System.Convert]::ToBase64String($EncryptedBytes)
    }

    try
    {
        #Load System.Data for interacting with the SQL database
        [System.Reflection.Assembly]::loadwithpartialname('System.Data') | Out-Null
        
        #Open the Database Connection
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$sqlServer;Database=$sqlDatabase;Trusted_Connection=True;"
        $conn.Open()

        # Prepare the query
        if($EncryptedUser -ne $null){ $cmdString = "INSERT into dbo.SecureCredentials VALUES (@SSCredentialPurpose,@SSEncryptedUsername,@SSEncryptedPassword,@SSCertificateThumbprint);" }
        else{ $cmdString = "INSERT into dbo.SecureCredentials VALUES (@SSCredentialPurpose,'',@SSEncryptedPassword,@SSCertificateThumbprint);" }
        $cmd = New-Object System.Data.SqlClient.SqlCommand($cmdString,$conn)
        $cmd.CommandTimeout = 30
        [Void]$cmd.Parameters.AddWithValue("@SSCredentialPurpose",$CredentialPurpose)
        if($EncryptedUser -ne $null){ [Void]$cmd.Parameters.AddWithValue("@SSEncryptedUsername",$EncryptedUser) }
        [Void]$cmd.Parameters.AddWithValue("@SSEncryptedPassword",$EncryptedPwd)
        [Void]$cmd.Parameters.AddWithValue("@SSCertificateThumbprint",$CertificateThumbprint)

        # Execute the query
        $ds=New-Object system.Data.DataSet
        $da=New-Object system.Data.SqlClient.SqlDataAdapter($cmd)
        $da.fill($ds) | Out-Null
    }
    catch
    {
        Write-Output "There was an error adding the entry into the database. The error reported was: `n$($_.Exception.Message)"
        $conn.Close() # ALWAYS close your SQL connections
        $EncryptedPwd = $null # flush our variables
        $EncryptedUser = $null
        $CredentialPurpose = $null
        return
    }
    $conn.Close() # ALWAYS close your SQL connections
    $EncryptedPwd = $null # flush our variables
    $EncryptedUser = $null
    $CredentialPurpose = $null
    Write-Output "Successfully added credentials to the database."
}

Function Get-PSCredCredential()
{
    <#
    .SYNOPSIS
    Grabs the credentials from the database and decrypts them with a certificate.
    
    .DESCRIPTION
    Using the credential purpose, it grabs the matching row from the database and
    then decrypts the password and username with the certificate that macthes the
    thumbprint stored in the database. The password can be returned as a secure
    string (default) or as a cleartext password using the -Insecure switch.
    
    .PARAMETER sqlServer
    The name of the SQL server you want to connect to. This can also be automatically 
    populated by running the New-PSCredSQLConnection command.
    
    .PARAMETER sqlDatabase
    The name of the SQL database you want to connect to. This can also be automatically 
    populated by running the New-PSCredSQLConnection command.
    
    .PARAMETER CredentialPurpose
    The credential purpose you wish to lookup.
    
    .PARAMETER Insecure
    A switch that allows you to return the password in cleartext instead of a secure string
    
    .EXAMPLE
    PS> Get-PSCredCredential "SQL SA Account for SQL01"

    .EXAMPLE
    PS> Get-PSCredCredential "SQL SA Account for SQL01" -Insecure
    #>
    Param
    (
        # SQL Server FQDN
        [Parameter(Mandatory=$false,
        HelpMessage="Enter the fully qualified domain name of the SQL server you will connect to.")]
        [string]
        $sqlServer=$script:PSCredServer,

        # SQL Server Database
        [Parameter(Mandatory=$false,
        HelpMessage="Enter the name of the database you'll be connecting to.")]
        [string]
        $sqlDatabase=$script:PSCredDatabase,

        # The purpose of the credentials
        [Parameter(Mandatory=$true,
        HelpMessage="Enter the purpose of the credentials.")]
        [string]
        $CredentialPurpose,
        
        # Switch to reveal the password in cleartext
        [Parameter(Mandatory=$false)]
        [switch]
        $Insecure
    )
    try
    {
        #Load System.Data for interacting with the SQL database
        [System.Reflection.Assembly]::loadwithpartialname('System.Data') | Out-Null
        
        #Open the Database Connection
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$sqlServer;Database=$sqlDatabase;Trusted_Connection=True;"
        $conn.Open()

        #Prepare the query
        $cmdString = "SELECT * from dbo.SecureCredentials WHERE CredentialPurpose=@SSCredentialPurpose;"
        $cmd = New-Object System.Data.SqlClient.SqlCommand($cmdString,$conn)
        $cmd.CommandTimeout = 30
        [Void]$cmd.Parameters.AddWithValue("@SSCredentialPurpose",$CredentialPurpose)

        # Execute the query
        $ds=New-Object system.Data.DataSet
        $da=New-Object system.Data.SqlClient.SqlDataAdapter($cmd)
        $da.fill($ds) | Out-Null
    }
    catch
    {
        Write-Output "There was an error finding the entry in the database. The error reported was: `n$($_.Exception.Message)"
        $conn.Close() # ALWAYS close your SQL connections
        $CredentialPurpose = $null # flush our variables
        return
    }
    $conn.Close() # ALWAYS close your SQL connections
    $CredentialPurpose = $null # flush our variables

    # Check to make sure we found the database entry
    if($ds.Tables.CertificateThumbprint -eq $null)
    {
        Write-Output "Unable to find that credential purpose in the database"
        return
    }
    
    # Find the certificate
    $Cert = $null
    $Cert = Get-PSCredCertificate -CertThumbprint "$($ds.Tables.CertificateThumbprint)"
    if($Cert -eq $null)
    {
        Write-Output "Unable to find the certificate associated with these credentials."
        return
    }

    # Start the fun... load the encrypted password and username into a variable
    $EncryptedPwd = "$($ds.Tables.EncryptedPassword)"
    $EncryptedUsr = "$($ds.Tables.EncryptedUsername)"
    $ds = $null # flush our variables
    
    # New Object to return the username and/or password object
    $returnCredentials = New-Object PSObject

    # Username first
    if(-not ($EncryptedUsr -eq ""))
    {
        $DecryptedUsername = [system.text.encoding]::UTF8.GetString($Cert.PrivateKey.Decrypt([System.Convert]::FromBase64String($EncryptedUsr), $true))
        Add-Member -InputObject $returnCredentials -MemberType NoteProperty -Name Username -Value "$DecryptedUsername"    
    }

    # Password last
    if($Insecure)
    {
        $DecryptedPassword = [system.text.encoding]::UTF8.GetString($Cert.PrivateKey.Decrypt([System.Convert]::FromBase64String($EncryptedPwd), $true))
    }
    else
    {
        $DecryptedPassword = ConvertTo-SecureString -String ([system.text.encoding]::UTF8.GetString($Cert.PrivateKey.Decrypt([System.Convert]::FromBase64String($EncryptedPwd), $true))) -AsPlainText -Force
    }
    Add-Member -InputObject $returnCredentials -MemberType NoteProperty -Name Password -Value $DecryptedPassword
    
    # Flush our variables
    $DecryptedUsername = $null
    $DecryptedPassword = $null

    # Return Credentials
    $returnCredentials
}

Function Remove-PSCredCredential()
{
    <#
    .SYNOPSIS
    Removes credentials from database.
    
    .DESCRIPTION
    Removes credentials from the database using the credential purpose as a key.
    
    .PARAMETER sqlServer
    The name of the SQL server you want to connect to. This can also be automatically 
    populated by running the New-PSCredSQLConnection command.
    
    .PARAMETER sqlDatabase
    The name of the SQL database you want to connect to. This can also be automatically 
    populated by running the New-PSCredSQLConnection command.
    
    .PARAMETER CredentialPurpose
    The unique name that describes the purpose of the credentials.
    
    .EXAMPLE
    PS> Remove-PSCredCredential -CredentialPurpose "SQL SA Account for SQL01"
    #>
    Param
    (
        # SQL Server FQDN
        [Parameter(Mandatory=$false,
        HelpMessage="Enter the fully qualified domain name of the SQL server you will connect to.")]
        [string]
        $sqlServer=$script:PSCredServer,

        # SQL Server Database
        [Parameter(Mandatory=$false,
        HelpMessage="Enter the name of the database you'll be connecting to.")]
        [string]
        $sqlDatabase=$script:PSCredDatabase,

        # The purpose of the credentials
        [Parameter(Mandatory=$true,
        HelpMessage="Enter the purpose of the credentials.")]
        [string]
        $CredentialPurpose
    )
    try
    {
        #Load System.Data for interacting with the SQL database
        [System.Reflection.Assembly]::loadwithpartialname('System.Data') | Out-Null
        
        #Open the Database Connection
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$sqlServer;Database=$sqlDatabase;Trusted_Connection=True;"
        $conn.Open()

        #Prepare the query
        $cmdString = "DELETE from dbo.SecureCredentials WHERE CredentialPurpose=@SSCredentialPurpose;"
        $cmd = New-Object System.Data.SqlClient.SqlCommand($cmdString,$conn)
        $cmd.CommandTimeout = 30
        [Void]$cmd.Parameters.AddWithValue("@SSCredentialPurpose",$CredentialPurpose)

        #Execute the query
        $ds=New-Object system.Data.DataSet
        $da=New-Object system.Data.SqlClient.SqlDataAdapter($cmd)
        $da.fill($ds) | Out-Null
    }
    catch
    {
        Write-Output "There was an error removing the entry from the database. The error reported was: `n$($_.Exception.Message)"
        $conn.Close() # ALWAYS close your SQL connections
        $CredentialPurpose = $null # flush our variables
        return
    }
    $conn.Close() # ALWAYS close your SQL connections
    $CredentialPurpose = $null # flush our variables
    Write-Output "Successfully removed the credentials from the database."
}
