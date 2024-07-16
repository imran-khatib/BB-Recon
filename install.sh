#!/bin/bash

# Function to check and install packages
install_package() {
  package=$1
  if ! dpkg -l | grep -q $package; then
    echo "Installing $package..."
    sudo apt-get install -y $package
  else
    echo "$package is already installed."
  fi
}

# Update and upgrade the system
echo "Updating and upgrading the system..."
sudo apt-get update -y && sudo apt-get upgrade -y

# Install required packages
echo "Installing required packages..."
install_package curl
install_package git
install_package python3
install_package python3-pip
install_package ruby
install_package terminator
install_package make
install_package build-essential

# Install Golang
echo "Installing Golang..."
if ! command -v go &> /dev/null; then
  wget https://dl.google.com/go/go1.16.3.linux-amd64.tar.gz
  sudo tar -C /usr/local -xzf go1.16.3.linux-amd64.tar.gz
  echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.profile
  source ~/.profile
  rm go1.16.3.linux-amd64.tar.gz
else
  echo "Golang is already installed."
fi

# Create tools directory
TOOLS_DIR=~/tools
mkdir -p $TOOLS_DIR

# Install tools
echo "Installing tools..."

# Assetfinder
echo "Installing Assetfinder..."
go install github.com/tomnomnom/assetfinder@latest

# Subfinder
echo "Installing Subfinder..."
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass
echo "Installing Amass..."
go install -v github.com/OWASP/Amass/v3/...@latest

# Findomain
echo "Installing Findomain..."
cd $TOOLS_DIR
git clone https://github.com/Findomain/Findomain.git
cd Findomain
cargo build --release

# Shuffledns
echo "Installing Shuffledns..."
GO111MODULE=on go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# Naabu
echo "Installing Naabu..."
GO111MODULE=on go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Httpx
echo "Installing Httpx..."
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Nuclei
echo "Installing Nuclei..."
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Smuggler
echo "Installing Smuggler..."
cd $TOOLS_DIR
git clone https://github.com/defparam/smuggler.git

# Corsy
echo "Installing Corsy..."
cd $TOOLS_DIR
git clone https://github.com/s0md3v/Corsy.git
pip3 install -r Corsy/requirements.txt

# WhatWeb
echo "Installing WhatWeb..."
cd $TOOLS_DIR
git clone https://github.com/urbanadventurer/WhatWeb.git
cd WhatWeb
bundle install

# Eyewitness
echo "Installing Eyewitness..."
cd $TOOLS_DIR
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness/Python/setup
./setup.sh

# Relative URL Extractor
echo "Installing Relative URL Extractor..."
cd $TOOLS_DIR
git clone https://github.com/jobertabma/relative-url-extractor.git

# Waybackurls
echo "Installing Waybackurls..."
go install github.com/tomnomnom/waybackurls@latest

# Unfurl
echo "Installing Unfurl..."
go install github.com/tomnomnom/unfurl@latest

# GF
echo "Installing GF..."
go install github.com/tomnomnom/gf@latest
mkdir ~/.gf
cp -r $TOOLS_DIR/gf/examples ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns
mv Gf-Patterns/*.json ~/.gf

# Gobuster
echo "Installing Gobuster..."
go install github.com/OJ/gobuster/v3@latest

# Feroxbuster
echo "Installing Feroxbuster..."
cargo install feroxbuster

# Masscan
echo "Installing Masscan..."
cd $TOOLS_DIR
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install

# FFUF
echo "Installing FFUF..."
go install github.com/ffuf/ffuf@latest

# Install SecLists
echo "Installing SecLists..."
cd $TOOLS_DIR
git clone https://github.com/danielmiessler/SecLists.git

echo "All tools installed successfully!"
