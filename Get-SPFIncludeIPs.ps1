#region helperFunctions
function Get-SpfRecord {
    param(
        [parameter(Position = 0)]
        [string] $domain
    )
    (Resolve-DnsName $($domain.Split('@') | Select-Object -Last 1) -Type txt | Where-Object Strings -like "*spf*" | Select-Object -ExpandProperty strings).Split(" ")
}
# this function is copied from:
# https://gallery.technet.microsoft.com/scriptcenter/List-the-IP-addresses-in-a-60c5bb6b
function Get-IPrange {
    <# 
  .SYNOPSIS  
    Get the IP addresses in a range 
  .EXAMPLE 
   Get-IPrange -start 192.168.8.2 -end 192.168.8.20 
  .EXAMPLE 
   Get-IPrange -ip 192.168.8.2 -mask 255.255.255.0 
  .EXAMPLE 
   Get-IPrange -ip 192.168.8.3 -cidr 24 
    #> 
 
    param 
    ( 
        [string]$start, 
        [string]$end, 
        [string]$ip, 
        [string]$mask, 
        [int]$cidr 
    ) 
 
    function IP-toINT64 () { 
        param ($ip) 
 
        $octets = $ip.split(".") 
        return [int64]([int64]$octets[0] * 16777216 + [int64]$octets[1] * 65536 + [int64]$octets[2] * 256 + [int64]$octets[3]) 
    } 
 
    function INT64-toIP() { 
        param ([int64]$int) 

        return (([math]::truncate($int / 16777216)).tostring() + "." + ([math]::truncate(($int % 16777216) / 65536)).tostring() + "." + ([math]::truncate(($int % 65536) / 256)).tostring() + "." + ([math]::truncate($int % 256)).tostring() )
    } 
 
    if ($ip) { $ipaddr = [Net.IPAddress]::Parse($ip) } 
    if ($cidr) { $maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1" * $cidr + "0" * (32 - $cidr)), 2)))) } 
    if ($mask) { $maskaddr = [Net.IPAddress]::Parse($mask) } 
    if ($ip) { $networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address) } 
    if ($ip) { $broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address)) } 
 
    if ($ip) { 
        $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring 
        $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
    }
    else { 
        $startaddr = IP-toINT64 -ip $start 
        $endaddr = IP-toINT64 -ip $end 
    } 
 
 
    for ($i = $startaddr; $i -le $endaddr; $i++) { 
        INT64-toIP -int $i 
    }

}

#endregion

function Get-SPFIncludeIPs () {
    [cmdletBinding()]
    param(
        [string] $domain
    )
    [System.Collections.ArrayList] $spfRecord = Get-SpfRecord $domain
    # while there is an unexpanded include in the SPF record do some stuff :)
    while (($spfRecord | Where-Object { $_ -match "include" })) {
        $toRemove = New-Object System.Collections.ArrayList
        $recordToAdd = New-Object System.Collections.ArrayList
        
        $spfRecord | Where-Object { $_ -match "include" } | ForEach-Object {
            $toRemove.Add($_) | Out-Null
            # split based on the include:record format
            $foo = $_.Split(":")[1]
            # get the SPF record for the include
            $record = Get-SpfRecord $foo
            # add to colection for later adding
            $recordToAdd.Add($record) | Out-Null
        }
        # remove the already resolved includes
        $toRemove | ForEach-Object {
            Write-Verbose "removing $_"
            $spfRecord.Remove($_) | Out-Null
        }
        # add each member of the expanded "includes"
        [array] $recordToAdd | ForEach-Object {
            $_ | ForEach-Object {
                $spfRecord.Add($_) | Out-Null
            }
        }
    }
    # filter only the ip4 ranges/single IPs
    $ip4All = $spfRecord | Where-Object { $_ -match "ip4" }
    [System.Collections.ArrayList] $ip4Single = ($ip4All | Where-Object { $_ -notmatch "/" }) -as [array]
    [System.Collections.ArrayList] $ip4Ranges = ($ip4All | Where-Object { $_ -match "/" }) -as [array]

    if ($null -eq $ip4Single) {
        $ip4Single = New-Object System.Collections.ArrayList
    }
    # resolve A records, if any are included
    $aRecords = $spfRecord | Where-Object { $_ -match "^a:\w+|^\+a:\w+" }
    if ($aRecords) {
        ($aRecords | ForEach-Object {
                Resolve-DnsName $($_.Split(":")[1])
            }).IPAddress | ForEach-Object {
            $ip4Single.Add($_) | Out-Null
        }
    }

    # expand the IP ranges to single IPs
    $ip4Ranges | ForEach-Object {
        $temp = $_.Split("/")
        $range = Get-IPrange -ip $($temp[0].Split(":")[1]) -cidr $temp[1]
        $range | ForEach-Object {
            $ip4Single.Add($_) | Out-Null
        }
    }
    $ip4Single.Replace("ip4:", "")
}

$ip4Single = Get-SPFIncludeIPs -domain "example.com"
$messages = Import-Csv .\messagelist_all.csv -Delimiter ';' -Encoding unicode

$messages | ForEach-Object {
    $verdict = $_.IP -in $ip4Single
    "{0} - {1}" -f $_.IP, $verdict
    $hostName = (Resolve-DnsName $_.IP -QuickTimeout -ErrorAction SilentlyContinue).NameHost -join ","
    Add-Member -InputObject $_ -Name "Hostname" -Value $hostName -MemberType NoteProperty
    Add-Member -InputObject $_ -Name "IP in SPF" -Value $verdict -MemberType NoteProperty
}
$messages | Export-Csv messages_checked.csv -NoTypeInformation -Delimiter ';' -Encoding unicode
