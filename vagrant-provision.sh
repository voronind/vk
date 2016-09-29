#!/bin/bash

sudo apt-get update; sudo apt-get upgrade

sudo apt-get install -y python-dev
sudo apt-get install -y python3-dev python3-pip

sudo pip3 install --upgrade pip virtualenv\>=15

virtualenv ~/.virtualenvs/vk
~/.virtualenvs/vk/bin/pip install -r requirements.txt

echo '' >> ~/.bashrc
echo 'source ~/.virtualenvs/vk/bin/activate' >> ~/.bashrc
echo 'cd ~/vk' >> ~/.bashrc
echo 'export PYTHONPATH=.' >> ~/.bashrc
