import sys
from auth import MiBand3
from cursesmenu import *
from cursesmenu.items import *
import time
import os

MAC_ADDR= 'D9:C6:8D:E1:FF:3A'
def l(x):
    print 'Realtime heart BPM:', x
    band.stop_realtime()
    time.sleep(50)
    band.start_raw_data_realtime(heart_measure_callback=l)
band = MiBand3(MAC_ADDR, debug=True)
band.setSecurityLevel(level = "medium")

band.authenticate()

band.start_raw_data_realtime(heart_measure_callback=l)
