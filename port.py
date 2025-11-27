

import argparse
import socket # for connecting
from colorama import init, Fore

from threading import Thread, Lock
from queue import Queue

# some colors
init()
GREEN = Fore.GREEN
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX
blue = Fore.BLUE
red = Fore.RED
yl = Fore.YELLOW

# number of threads, feel free to tune this parameter as you wish
N_THREADS = 200
# thread queue
q = Queue()
print_lock = Lock()

def port_scan(port):
    """
    Scan a port on the global variable `host`
    """
    try:
        s = socket.socket()
        s.connect((host, port))
    except:
        with print_lock:
            print(f"{red}{host:15}:{port:5} is closed  {RESET}", end='\')
    else:
        with print_lock:
            print(f"{GREEN}{host:15}:{port:5} is open    {RESET}")
    finally:
        s.close()
#banner script
print (red+"""

$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$%$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$ _______  _______ """+red, blue+""" _        ______   _______  _______ """+blue, red+"""$$$$$$$$$$$$$$
$$$$$$$$$$$$$(  ____ )(  __   )"""+red, blue+"""( (    /|/ ___  \(  ____ )(  ____ \"""+blue, red+"""$$$$$$$$$$$$$
$$$$$$$$$$$$$| (    )|| (  )  |"""+red, blue+"""|  \ ( |\   \ \ (    )|| (    \"""+blue, red+"""$$$$$$$$$$$$$
$$$$$$$$$$$$$| (____)|| | /   |"""+red, blue+"""|   \| |   ___) /| (____)|| (_____ """+blue, red+"""$$$$$$$$$$$$$
$$$$$$$$$$$$$|  _____)| (/ /) |"""+red, blue+"""| (\\ |  (___ ( |     __)(_____  )"""+blue, red+"""$$$$$$$$$$$$$
$$$$$$$$$$$$$| (      |   / | |"""+red, blue+"""| | \  |      ) \ (\(         ) |"""+blue, red+"""$$$$$$$$$$$$$
$$$$$$$$$$$$$| )      |  (__) |"""+red, blue+"""| )  \ |/\__/  /| ) \\_/\___) |"""+blue, red+"""$$$$$$$$$$$$$
$$$$$$$$$$$$$|/       (_______)"""+red, blue+"""|/    )_)\_____/ |/   \_/\______) """+blue, GREEN+"""$$$$$$$$$$$$$
$$$$$$$$$$$$$                                                      $$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$  """+GREEN+"""
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
               ==========================================
               [---]            """+GREEN+"""P0N3RS"""+GREEN+"""              [---]
               =========================================
               [---]  """+red+""" Created By M1S73R-4N0NYM0U5 """+GREEN+""" [---]
               ==========================================
               [---]      """+yl+""" Made for port scanning"""+GREEN+"""   [---]
               ==========================================
"""+red)



def scan_thread():
    global q
    while True:
        # get the port number from the queue
        worker = q.get()
        # scan that port number
        port_scan(worker)
        # tells the queue that the scanning for that port
        # is done
        q.task_done()


def main(host, ports):
    global q
    for t in range(N_THREADS):
        # for each thread, start it
        t = Thread(target=scan_thread)
        # when we set daemon to true, that thread will end when the main thread ends
        t.daemon = True
        # start the daemon thread
        t.start()

    for worker in ports:
        # for each port, put that port into the queue
        # to start scanning
        q.put(worker)

    # wait the threads ( port scanners ) to finish
    q.join()


if __name__ == "__main__":
    # parse some parameters passed
    parser = argparse.ArgumentParser(description="Simple port scanner")
    parser.add_argument("host", help="Host to scan.")
    parser.add_argument("--ports", "-p", dest="port_range", default="1-65535", help="Port range to scan, default is 1-65535 (all ports)")
    args = parser.parse_args()
    host, port_range = args.host, args.port_range


    start_port, end_port = port_range.split("-")
    start_port, end_port = int(start_port), int(end_port)


    ports = [ p for p in range(start_port, end_port)]

    main(host, ports)
##############################################################
#####################                #########################
#####################   END OF TOOL  #########################
#####################                #########################
##############################################################
#This Tool by ITH-Pgm
#Have a nice day :)
#GoodBye
