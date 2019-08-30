import sys
from auth import MiBand3
from cursesmenu import *
from cursesmenu.items import *
import time
import os

MAC_ADDR= 'D9:C6:8D:E1:FF:3A'

name = raw_input("Enter your name:")
age = input ("Enter your age :")


def l(x):
    if (age < 60 ) and (age > 55):
        print 'Realtime heart BPM:', x
        if(71<x or 49 > x):
            print 'Your Heart rate is abnormal'
    elif (age < 65 ) and (age > 60):
        print 'Realtime heart BPM:', x
        if(71<x or 49 > x):
            print 'Your Heart rate is abnormal'
    elif (age < 70 ) and (age > 65):
        print 'Realtime heart BPM:', x
        if(71<x or 49 > x):
            print 'Your Heart rate is abnormal'

    else:
        print 'Realtime heart BPM:', x
    band.stop_realtime()
    time.sleep(50)
    band.start_raw_data_realtime(heart_measure_callback=l)

def heart_beat():
    band.start_raw_data_realtime(heart_measure_callback=l)
    raw_input('Press Enter to continue')

print 'Attempting to connect to ', MAC_ADDR

band = MiBand3(MAC_ADDR, debug=True)
band.setSecurityLevel(level = "medium")

# Authenticate the MiBand
if len(sys.argv) > 2:
    if band.initialize():
        print("Initialized...")
    band.disconnect()
    sys.exit(0)
else:
    band.authenticate()
heart_beat()
