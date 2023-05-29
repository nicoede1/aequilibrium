#!/bin/bash

sudo apt-get -y --force-yes update
sudo apt-get -y --force-yes install xfce4-session xfce4-goodies x2goserver x2goserver-xsession gedit apache2
wget https://nyu.box.com/shared/static/d6btpwf5lqmkqh53b52ynhmfthh2qtby.tgz -O media.tgz
sudo tar -v -xzf media.tgz -C /var/www/html/
git clone https://github.com/pari685/AStream  
