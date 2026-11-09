# LINxAI agentless Windows lab - run ONCE in an elevated PowerShell (Run as administrator).
# Installs Windows' built-in OpenSSH server (Manual start, not Automatic), starts it and
# authorizes ONLY the LINxAI lab public key. Nothing else is changed.
# Undo later:  Stop-Service sshd; Set-Service sshd -StartupType Disabled
#              and remove the "linxai-windows-lab" line from C:\ProgramData\ssh\administrators_authorized_keys
$ErrorActionPreference = 'Stop'
$cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
if ($cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name $cap.Name | Out-Null }
Set-Service sshd -StartupType Manual
Start-Service sshd
$key  = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHqEPihd2gkajAQsZ3/ottYmxVz/TXJfB4l5pg+S3jlm linxai-windows-lab'
$file = 'C:\ProgramData\ssh\administrators_authorized_keys'
if (-not (Test-Path $file) -or -not (Select-String -Path $file -SimpleMatch 'linxai-windows-lab' -Quiet)) {
    Add-Content -Path $file -Value $key -Encoding ascii
}
icacls $file /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
Get-Service sshd | Format-Table Name, Status, StartType
& "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe" -lf 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub'
Write-Host 'LINxAI Windows lab ready. Tell Claude: windows ready'
