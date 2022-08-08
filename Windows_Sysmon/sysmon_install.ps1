$wazuh_repo = 'packages.wazuh.com'
$wazuh_major = '4.x'
$wazuh_package = 'wazuh-agent-4.3.6-1.msi'
$wazuh_downloadlink = 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.3.6-1.msi'
$WAZUH_MANAGER="your_wazuh_manager"
$WAZUH_REGISTRATION_SERVER="your_wazuh_manager"
$WAZUH_MANAGER_PORT="1514"
$WAZUH_PROTOCOL="TCP"
$WAZUH_REGISTRATION_PASSWORD="your_registration_password"
$WAZUH_AGENT_GROUP="your_agent_group"
$sysinternals_repo = 'download.sysinternals.com'
$sysinternals_downloadlink = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
$sysinternals_folder = 'C:\Program Files\sysinternals'
$sysinternals_zip = 'SysinternalsSuite.zip'
$sysmonconfig_downloadlink = 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml'
$sysmonconfig_file = 'sysmonconfig-export.xml'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (Test-Path -Path $sysinternals_folder) {
    write-host ('Sysinternals folder already exists')
} else {
  $OutPath = $env:TMP
  $output = $sysinternals_zip
  New-Item -Path "C:\Program Files" -Name "sysinternals" -ItemType "directory"
  $X = 0
  do {
    Write-Output "Waiting for network"
    Start-Sleep -s 5
    $X += 1
  } until(($connectreult = Test-NetConnection $sysinternals_repo -Port 443 | ? { $_.TcpTestSucceeded }) -or $X -eq 3)

  if ($connectreult.TcpTestSucceeded -eq $true){
    Try
    {
    write-host ('Downloading and copying Sysinternals Tools to C:\Program Files\sysinternals...')
    Invoke-WebRequest -Uri $sysinternals_downloadlink -OutFile $OutPath\$output
    Expand-Archive -path $OutPath\$output -destinationpath $sysinternals_folder
    Start-Sleep -s 10
    Invoke-WebRequest -Uri $sysmonconfig_downloadlink -OutFile $OutPath\$sysmonconfig_file
    $serviceName = 'Sysmon64'
    If (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    write-host ('Sysmon Is Already Installed')
    } else {
    Invoke-Command {reg.exe ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f}
    Invoke-Command {reg.exe ADD HKU\.DEFAULT\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f}
    Start-Process -FilePath $sysinternals_folder\Sysmon64.exe -Argumentlist @("-i", "$OutPath\$sysmonconfig_file")
    }
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Error -Message "$ErrorMessage $FailedItem"
        exit 1
    }
    Finally
    {
        Remove-Item -Path $OutPath\$output
    }

  } else {
      Write-Output "Unable to connect to Sysinternals Repo"
  }
}
$serviceName = 'OssecSvc'
If (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    write-host ('Wazuh Agent Is Already Installed')
} else {
    $OutPath = $env:TMP
    $output = $wazuh_package

    $installArgs = @(
      "/i $OutPath\$output"
      "/q"
      "WAZUH_MANAGER=`"$WAZUH_MANAGER`""
      "WAZUH_REGISTRATION_SERVER=`"$WAZUH_REGISTRATION_SERVER`""
      "WAZUH_MANAGER_PORT=`"$WAZUH_MANAGER_PORT`""
      "WAZUH_PROTOCOL=`"$WAZUH_PROTOCOL`""
      "WAZUH_REGISTRATION_PASSWORD=`"$WAZUH_REGISTRATION_PASSWORD`""
      "WAZUH_AGENT_GROUP=`"$WAZUH_AGENT_GROUP`""
    )

    $X = 0
    do {
      Write-Output "Waiting for network"
      Start-Sleep -s 5
      $X += 1
    } until(($connectreult = Test-NetConnection $wazuh_repo -Port 443 | ? { $_.TcpTestSucceeded }) -or $X -eq 3)

    if ($connectreult.TcpTestSucceeded -eq $true){
      Try
      {
      Invoke-WebRequest -Uri $wazuh_downloadlink -OutFile $OutPath\$output
      write-host ('Installing Wazuh Agent...')
      Start-Process "msiexec.exe" -ArgumentList $installArgs -Wait
      Start-Sleep -s 10

      }
      Catch
      {
          $ErrorMessage = $_.Exception.Message
          $FailedItem = $_.Exception.ItemName
          Write-Error -Message "$ErrorMessage $FailedItem"
          exit 1
      }
      Finally
      {
          Remove-Item -Path $OutPath\$output
      }

    } else {
        Write-Output "Unable to connect to Wazuh Repo"
}
}
