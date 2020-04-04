#Install SSH for Powershell
#Import-module Posh-ssh -Force -Verbose

#Login
$Login="admin"

#Password
$Password = "papap55524jja"

#Credential  or Password encryption
$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force -ErrorAction SilentlyContinue
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $Login,$SecurePassword        


#Fonction de fermeture de la session
     function Disconnect-SSH{
        [CmdletBinding(ConfirmImpact='Low')]
        param([object]$IDsession)
        begin{
        $ID=  $IDsession.Host
        }
            process{
            if(Remove-SSHSession $IDsession){
                     Write-Host "=============================="
                     Write-Host   "Session SSH: $ID Closed"
            }else{
                write-host "Impossible to close the $ID session" 
            }

        }
     } 

#
     function Secure-Password{
        [CmdletBinding(ConfirmImpact='Low')]
        param([string]$Password)
        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        return $SecurePassword
     }

#Fonction Change-Community
     function Change-Community{
    [CmdletBinding(ConfirmImpact='Low')]
        param([object]$SessionSSH,[string]$OldCommunity,[string]$NewCommunity,[int]$VersionSNMP)
        #Get-Identity
        $GetIdentity= Invoke-SSHCommandStream -SSHSession $SessionSSH -Command "system identity print" 
        $Identity = (($GetIdentity -split ':')[1]).TrimStart()
        $cod1= Invoke-SSHCommandStream -Command "/snmp community set $OldCommunity name=$NewCommunity" -SSHSession $SessionSSH 
        $cod2= Invoke-SSHCommandStream -Command "/snmp set enabled=yes trap-community=$NewCommunity trap-version=$VersionSNMP" -SSHSession $SessionSSH
        return $Identity      
}

#Open-SshSessionAndChangeCommunity
Function Open-SshSessionAndChangeCommunity{
    [CmdletBinding(ConfirmImpact='Low')]
    param([string]$IPDevice,[string]$OldCommunity,[string]$NewCommunity,[object]$Credential,[int]$VersionSNMP)

    if(($Session1 = New-SSHSession -ComputerName $IPDevice -Credential $Credential -Port 22 -Force  -ErrorAction SilentlyContinue).Connected){
            
            #verbose
            #Write-Host "Session Open" -ForegroundColor DarkGreen 
                    
            #Change Community
            $IdentityRouter= Change-Community -SessionSSH $Session1 -OldCommunity $OldCommunity -NewCommunity $NewCommunity -VersionSNMP $VersionSNMP -ErrorAction SilentlyContinue -Verbose
            
            #verbose
            Write-Host "Device: $IdentityRouter `nCommunity: $NewCommunity `nSNMP_Version: $VersionSNMP `nSNMP: Enabled" -ForegroundColor Green


            #Fermeture-Session
            Disconnect-SSH -IDsession $Session1 -ErrorAction SilentlyContinue
     }
}




#Main

function Mikrotik-ChangeCommunitySNMP {
    [CmdletBinding(ConfirmImpact='Low')]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [System.Net.IPAddress]$StartAddress,
        [parameter(Mandatory = $true, Position = 1)]
        [System.Net.IPAddress]$EndAddress,
        [int]$Interval = 30,
        [Switch]$RawOutput = $false,
        [string]$OldCommunity,
        [string]$NewCommunity,
        [int]$VersionSNMP,
        [object]$Credential
    )

    $timeout = 2000

    function New-Range ($start, $end) {

        [byte[]]$BySt = $start.GetAddressBytes()
        [Array]::Reverse($BySt)
        [byte[]]$ByEn = $end.GetAddressBytes()
        [Array]::Reverse($ByEn)
        $i1 = [System.BitConverter]::ToUInt32($BySt,0)
        $i2 = [System.BitConverter]::ToUInt32($ByEn,0)
        for($x = $i1;$x -le $i2;$x++){
            $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
            [Array]::Reverse($ip)
            [System.Net.IPAddress]::Parse($($ip -join '.'))
        }
    }
    
    $IPrange = New-Range $StartAddress $EndAddress

    $IpTotal = $IPrange.Count

    Get-Event -SourceIdentifier "ID-Ping*" | Remove-Event
    Get-EventSubscriber -SourceIdentifier "ID-Ping*" | Unregister-Event

    $IPrange | foreach{

        [string]$VarName = "Ping_" + $_.Address

        New-Variable -Name $VarName -Value (New-Object System.Net.NetworkInformation.Ping)

        Register-ObjectEvent -InputObject (Get-Variable $VarName -ValueOnly) -EventName PingCompleted -SourceIdentifier "ID-$VarName"

        (Get-Variable $VarName -ValueOnly).SendAsync($_,$timeout,$VarName)

        Remove-Variable $VarName

        try{

            $pending = (Get-Event -SourceIdentifier "ID-Ping*").Count

        }catch [System.InvalidOperationException]{}

        $index = [array]::indexof($IPrange,$_)
    
        Write-Progress -Activity "Envoie encours sur..." -Id 1 -status $_.IPAddressToString -PercentComplete (($index / $IpTotal)  * 100)

        Write-Progress -Activity "Délais d'attente ICMP MAx" -Id 2 -ParentId 1 -Status ($index - $pending) -PercentComplete (($index - $pending)/$IpTotal * 100)

        Start-Sleep -Milliseconds $Interval
    }

    Write-Progress -Activity "Re" -Id 1 -Status 'Veuillez patienter SVP' -PercentComplete 100 

    While($pending -lt $IpTotal){

        Wait-Event -SourceIdentifier "ID-Ping*" | Out-Null

        Start-Sleep -Milliseconds 10

        $pending = (Get-Event -SourceIdentifier "ID-Ping*").Count

        Write-Progress -Activity "Délais d'attente ICMP MAx" -Id 2 -ParentId 1 -Status ($IpTotal - $pending) -PercentComplete (($IpTotal - $pending)/$IpTotal * 100)
    }

    if($RawOutput){
        
        $Retour = Get-Event -SourceIdentifier "ID-Ping*" | ForEach { 
            If($_.SourceEventArgs.Reply.Status -eq "Success"){
                $_.SourceEventArgs.Reply
            }
            Unregister-Event $_.SourceIdentifier
            Remove-Event $_.SourceIdentifier
        }
    
    }else{
        
        $Retour = Get-Event -SourceIdentifier "ID-Ping*" | ForEach {   
            If($_.SourceEventArgs.Reply.Status -eq "Success"){  
                $_.SourceEventArgs.Reply | select @{
                      Name="IPAddress"   ; Expression={$_.Address}},
                    @{Name="Bytes"       ; Expression={$_.Buffer.Length}},
                    @{Name="Ttl"         ; Expression={$_.Options.Ttl}},
                    @{Name="ResponseTime"; Expression={$_.RoundtripTime}}    
            }
            Unregister-Event $_.SourceIdentifier
            Remove-Event $_.SourceIdentifier
        }
    }
    if($Retour -eq $Null){
        Write-Verbose "Scan-IPRange : Aucunne Adresse trouvée" -Verbose
    }


    #Mikrotik Connexion on Device UP...Protocole SSH
     $compteurDevice = 0
     $TotalDevice=($Retour.IPAddress.IPAddressToString).count
     $Retour| foreach{
        $compteurDevice++
        Write-Progress -Activity "Connexion SSH..." -Id 3 -status $_.IPAddress.IPAddressToString -PercentComplete (($compteurDevice / $TotalDevice)  * 100) 
        Start-Sleep -Milliseconds $Interval
      #Change Community  
      Open-SshSessionAndChangeCommunity -IPDevice $_.IPAddress.IPAddressToString -OldCommunity $OldCommunity -NewCommunity  $NewCommunity -Credential $Credential -VersionSNMP $VersionSNMP
     }
    
}

    



Mikrotik-ChangeCommunitySNMP -StartAddress 192.168.1.1 -EndAddress 192.168.1.12 -OldCommunity "public" -NewCommunity "NetAdmin" -Credential $Credential -VersionSNMP 2

