# iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/omair2084/misc/refs/heads/master/kali_vagrant_onWindows.ps1'))

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    throw
}

Write-Host "Starting software installations..." -ForegroundColor Green

Write-Host "Installing WinRAR..." -ForegroundColor Yellow
winget install -e --id RARLab.WinRAR -h --accept-package-agreements --accept-source-agreements

Write-Host "Installing Mozilla Firefox..." -ForegroundColor Yellow
winget install -e --id Mozilla.Firefox -h --accept-package-agreements --accept-source-agreements

Write-Host "Installing Python..." -ForegroundColor Yellow
winget install -e --id Python.Python.3.13 -h --accept-package-agreements --accept-source-agreements

Write-Host "Installing Windows Terminal..." -ForegroundColor Yellow
winget install -e --id Microsoft.WindowsTerminal -h --accept-package-agreements --accept-source-agreements

Write-Host "Installing Notepad++..." -ForegroundColor Yellow
winget install -e --id Notepad++.Notepad++ -h --accept-package-agreements --accept-source-agreements

Write-Host "Installing Visual Studio Code..." -ForegroundColor Yellow
winget install -e --id Microsoft.VisualStudioCode -h --accept-package-agreements --accept-source-agreements

Write-Host "Installing VirtualBox..." -ForegroundColor Yellow
winget install -e --id Oracle.VirtualBox -h --accept-package-agreements --accept-source-agreements

Write-Host "Installing Vagrant..." -ForegroundColor Yellow
winget install -e --id Hashicorp.Vagrant -h --accept-package-agreements --accept-source-agreements

#update paths
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)

Write-Host "Gear up process completed!" -ForegroundColor Green

Write-Host "Setting up Kali VM!" -ForegroundColor Green
Start-Sleep -Seconds 30
$vagSetup = @"
Vagrant.configure("2") do |config|
  config.vm.box = "kalilinux/rolling"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
  end

  config.vm.network "public_network" # Bridged adapter
  config.vm.network "forwarded_port", guest: 22, host: 2222 # SSH forwarding

config.vm.provision "shell", inline: <<-SHELL
    sudo wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg
    echo "deb https://kali.download/kali kali-rolling main contrib non-free non-free-firmware" | sudo tee /etc/apt/sources.list
    sudo apt update -y

    #sudo apt full-upgrade -y
    sudo apt install -y kali-linux-headless virtualbox-guest-utils pipx golang-go

    # Ensure pipx is ready to use
    pipx ensurepath

  SHELL
end

"@

# Create ISO with startup script
$vagSetup | Out-File -FilePath Vagrantfile -Encoding ascii

vagrant up
#On purpose
Start-Sleep -Seconds 30
vagrant up

Write-Host @"
Automated setup complete!
- SSH will be available on port 2222 after setup completes
- Connect using: ssh vagrant@localhost -p 2222
"@ -ForegroundColor Green
