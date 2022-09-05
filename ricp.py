#!/usr/bin/python3

"""
A protocol for transmitting the 0s and 1s of any interface over UDP in such a
way as that the client node sees the interface as physically local by way of
mac80211_hwsim for wireless and a tap interface for wired.

References
https://www.suse.com/c/creating-virtual-wlan-interfaces/
https://github.com/secdev/scapy/issues/724#
https://github.com/secdev/scapy/issues/1828
"""

import argparse
import base64
import binascii
import os
import nacl.secret
# import nacl.utils
# import nacl.pwhash
import psutil
import random
import signal
import sys
import time
from easyThread import Backgrounder
from easyThread import Backgrounder as SERVER
from easyThread import Backgrounder as LISTENER
from easyThread import Backgrounder as LISTENERII
from easyThread import EasyThread as LRET
from easyThread import Backgrounder as STAGER
from easyThread import Backgrounder as STAGERII
from easyThread import EasyThread as SRET
from easyThread import Backgrounder as REPEATER
from easyThread import Backgrounder as REPEATERII
from easyThread import EasyThread as RRET
from nacl.pwhash import argon2i
from queue import Queue
from pyDot11 import *
from scapy.all import *

# from scapy.sendrecv import __gen_send as gs

class Handler(object):
    """tap interface handler"""
    __slots__ = ['LR',
                 'SR',
                 'RR',
                 'args']

    def __init__(self, args):
        self.args = args
        if self.args.dstport is None:
            self.args.dstport = random.randint(0, 65535)
        if self.args.dstip is None:
            self.args.dstip = '127.0.0.1'
        # self.injSocket = conf.L2socket(iface = interface)
        # self.injSocket = conf.L3socket(iface = interface)

    def listener(self, work):
        """Listens for inbound on tap0

        Can probably be removed if the objects are combined which from vvv
        """
        while True:
            l = self.LR.get()
            if l is not None:
                # print(l.summary())
                # try:
                #     sendp(l, iface = 'tap1', verbose = 0)
                # except:
                #     pass
                self.LR.task_done()
        time.sleep(.000001)

    def stager(self, work):
        """Listens for inbound on the hybrid NIC and then sends to the source ip


        Most likely only the client needs this.
        """
        while True:
            s = self.SR.get()
            if s is not None:
                if args.weak is False:
                    sniff(iface = self.args.hybnic,
                          prn = lambda x: send(IP(dst = self.args.hybip)/\
                                               UDP(sport = random.randint(0, 65535), dport = int(self.args.hybport))/\
                                               Raw(load = box.encrypt(hexstr(x, onlyhex = 1).replace(' ', '').encode('utf-8'))),
                                               verbose = False),
                          store = 0)
                else:
                    sniff(iface = self.args.hybnic,
                          prn = lambda x: send(IP(dst = self.args.hybip)/\
                                               UDP(sport = random.randint(0, 65535), dport = int(self.args.hybport))/\
                                               Raw(load = x),
                                               verbose = False),
                          store = 0)

                self.SR.task_done()
            time.sleep(.000001)


    def repeater(self, work):
        """Listens for inbound on tap2"""
        while True:
            r = self.RR.get()
            ### Can enter here too for NIC control via the client.

            if r is not None:
                # print('Repeater received')
                # print(r.summary())
                ### This is our entry point for NIC control via the client.
                self.RR.task_done()
            time.sleep(.000001)



    def queueGen(self, qType, threads = 1):
        """Generate inner queues"""
        if qType == 'listener':
            ## Create a FIFO source queue
            lr = Handler(self.args)
            lr.LR = Queue()

            ## Add our function to EasyThread
            LRET.theThread = lr.listener
            lrEt = LRET(jobList = lr.LR, nThread = threads)

            ## Start the work
            def listener(self):
                lrEt.easyLaunch()
            LISTENER.theThread = listener
            lrBg = LISTENER()
            lrBg.easyLaunch()

            def tap0(self):
                sniff(iface = 'tap0', prn = lambda x: lr.LR.put(x))             ### HARDCODE

            ## Add our function to Backgrounder
            LISTENERII.theThread = tap0
            lrBgII = LISTENERII()

            ## Start the work
            lrBgII.easyLaunch()
            return lr, lrEt, lrBg

        if qType == 'stager':
            ## Create a FIFO source queue
            sr = Handler(self.args)
            sr.SR = Queue()

            ## Add our function to EasyThread
            SRET.theThread = sr.stager
            srEt = SRET(jobList = sr.SR, nThread = threads)

            ## Start the work
            def stager(self):
                srEt.easyLaunch()
            STAGER.theThread = stager
            srBg = STAGER()
            srBg.easyLaunch()

            def tap1(self):
                sniff(iface = 'tap1', prn = lambda x: sr.SR.put(x))             ### HARDCODE

            ## Add our function to Backgrounder
            STAGERII.theThread = tap1
            srBgII = STAGERII()

            ## Start the work
            srBgII.easyLaunch()
            return sr, srEt, srBg

        if qType == 'repeater':
            ## Create a FIFO source queue
            rr = Handler(self.args)
            rr.RR = Queue()

            ## Add our function to EasyThread
            RRET.theThread = rr.repeater
            rrEt = RRET(jobList = rr.RR, nThread = threads)

            ## Start the work
            def repeater(self):
                rrEt.easyLaunch()
            REPEATER.theThread = repeater
            rrBg = REPEATER()
            rrBg.easyLaunch()

            def tap2(self):
                sniff(iface = 'tap2', prn = lambda x: rr.RR.put(x))             ### HARDCODE

            ## Add our function to Backgrounder
            REPEATERII.theThread = tap2
            rrBgII = REPEATERII()

            ## Start the work
            rrBgII.easyLaunch()
            return rr, rrEt, rrBg


class Shared(object):
    __slots__ = ['args',
                 'box']

    def __init__(self, args, box):
        self.args = args
        self.box = box


    def wiredHandler(self):
        def snarf(packet):
            try:
                x=self.box.decrypt(packet[Raw].load)
                decrypted = Ether(binascii.unhexlify(x))
                sendp(decrypted, iface = self.args.snfnic, verbose = False)
            except Exception as E:
                print(E)
        return snarf


    def wiredHandlerWeak(self):
        def snarf(packet):
            try:
                sendp(Ether(packet[Raw].load), iface = self.args.snfnic, verbose = False)
            except Exception as E:
                print(E)
        return snarf


    def wirelessHandler(self):
        def snarf(packet):
            try:
                x=self.box.decrypt(packet[Raw].load)
                decrypted = RadioTap(binascii.unhexlify(x))
                sendp(decrypted, iface = self.args.snfnic, verbose = False)
            except Exception as E:
                print(E)
        return snarf


    def wirelessHandlerWeak(self):
        def snarf(packet):
            try:
                sendp(RadioTap(packet[Raw].load), iface = self.args.snfnic, verbose = False)
            except Exception as E:
                print(E)
        return snarf


    def clientSniff(self):
        """Copy from the monitoring NIC and inject to the sniff NIC"""
        if args.weak is False:
            if args.wired is False:
                PHANDLER = self.wirelessHandler()
            else:
                PHANDLER = self.wiredHandler()
        else:
            if args.wired is False:
                PHANDLER = self.wirelessHandlerWeak()
            else:
                PHANDLER  = self.wiredHandlerWeak()

        if self.args.weak is False:
            if self.args.wired is False:
                print('Sniffing wireless')
                try:
                    sniff(iface = self.args.monnic,
                          prn = PHANDLER,
                          lfilter = lambda y: y.haslayer(Raw),
                          store = 0,
                          filter = self.args.bpf)
                except Exception as E:
                    print(E)
            else:
                print('Sniffing wired')
                try:
                    sniff(iface = self.args.monnic,
                          prn = PHANDLER,
                          lfilter = lambda y: y.haslayer(Raw),
                          store = 0,
                          filter = self.args.bpf)
                except Exception as E:
                    print(E)
        else:
            if self.args.wired is False:
                print('Sniffing wireless')
                try:
                    sniff(iface = self.args.monnic,
                          prn = PHANDLER,
                          lfilter = lambda y: y.haslayer(Raw),
                          store = 0,
                          filter = self.args.bpf)
                except Exception as E:
                    print(E)
            else:
                print('Sniffing wired')
                try:
                    sniff(iface = self.args.monnic,
                          prn = PHANDLER,
                          lfilter = lambda y: y.haslayer(Raw),
                          store = 0,
                          filter = self.args.bpf)
                except Exception as E:
                    print(E)


    def serverSniff(self):
        """Copy from the monitoring NIC and inject to the client"""
        if args.weak is False:
            if args.wired is False:
                PHANDLER = self.wirelessHandler()
            else:
                PHANDLER = self.wiredHandler()
        else:
            if args.wired is False:
                PHANDLER = self.wirelessHandlerWeak()
            else:
                PHANDLER  = self.wiredHandlerWeak()

        if args.weak is False:
            sniff(iface = args.monnic,
                  prn = lambda x: send(IP(dst = args.dstip)/\
                                       UDP(sport = random.randint(0, 65535), dport = int(args.dstport))/\
                                       Raw(load = box.encrypt(hexstr(x, onlyhex = 1).replace(' ', '').encode('utf-8'))),
                                       verbose = args.verbose),
                  store = 0)
                  # filter = args.bpf)
        else:
            sniff(iface = args.monnic,
                  prn = lambda x: send(IP(dst = args.dstip)/\
                                       UDP(sport = random.randint(0, 65535), dport = int(args.dstport))/\
                                       Raw(load = x),
                                       verbose = args.verbose),
                  store = 0)
                  # filter = args.bpf)

def crtlC():
    """Handle CTRL+C."""
    def tmp(signal, frame):
        for i in psutil.process_iter():
            if 'ricp.py' in ' '.join(i.cmdline()) or 'ipython3' in ' '.join(i.cmdline()):
                i.kill()
    return tmp

def lrWork(self):
    """Listener work"""
    lret.easyLaunch()

def srWork(self):
    """Stager work"""
    sret.easyLaunch()

def rrWork(self):
    """Repeater work"""
    rret.easyLaunch()


if __name__ == '__main__':
    ## Args
    parser = argparse.ArgumentParser(description = 'placeholder')
    parser.add_argument('--bpf', help = 'Berkeley Packet Filter')
    parser.add_argument('--debug', action = 'store_true', help = 'client debug mode')
    parser.add_argument('--dstport', help = 'destination port', required = True)
    parser.add_argument('--dstip', help = 'destination ip', required = True)
    parser.add_argument('--hybip', help = 'hybrid ip')
    parser.add_argument('--hybnic', help = 'hybrid nic')
    parser.add_argument('--hybport', help = 'hybrid port')
    parser.add_argument('--key', help = 'key')
    parser.add_argument('--monnic', help = 'monitoring nic', required = True)
    parser.add_argument('--password', help = 'password')
    parser.add_argument('--salt', help = 'salt')
    parser.add_argument('--snfnic', help = 'sniffing nic')
    parser.add_argument('--stager', action = 'store_true', help = 'Setup the stager for tap mode')
    parser.add_argument('--verbose', action = 'store_true', help = 'verbosity on injection')
    parser.add_argument('--weak', action = 'store_true', help = 'Run without encryption')
    parser.add_argument('--wired', action = 'store_true', help = 'wired mode, requires -t')
    parser.add_argument('-c', action = 'store_true', help = 'run as client')
    parser.add_argument('-s', action = 'store_true', help = 'run as server')
    parser.add_argument('-t', action = 'store_true', help = 'tap mode')
    args = parser.parse_args()

    ## ADD SIGNAL HANDLER
    signal_handler = crtlC()
    signal.signal(signal.SIGINT, signal_handler)

    ## Encryption by default
    if args.weak is False:

        ## Minimum requirement
        if args.password is None:
            print('--password required without --weak')
            sys.exit(1)

        ## Encode the password
        password = args.password.encode('utf-8')

        ## salt
        if args.salt is None:
            # salt_size = nacl.pwhash.argon2i.SALTBYTES
            # salt = nacl.utils.random(salt_size)
            salt = os.urandom(argon2i.SALTBYTES)
            input('Random salt: ' + base64.b64encode(salt).decode('ascii') + '\nPress enter to continue')
        else:
            salt = base64.b64decode(args.salt)

        ## key
        if args.key is None:
            # kdf = nacl.pwhash.argon2i.kdf
            key = argon2i.kdf(nacl.secret.SecretBox.KEY_SIZE, password, salt)
            input('Derived key: ' + base64.b64encode(key).decode('ascii') + '\nPress enter to continue')
        else:
            key = base64.b64decode(args.key)

        ## Create the box
        box = nacl.secret.SecretBox(key)

    ## No encryption
    else:
        box = None
        print('Running in weak mode')

    ## Raw BPF
    if args.bpf is None:
        if args.c is True:
            args.bpf = 'udp port {0} and host {1}'.format(args.dstport, args.dstip)

    ## Stager constraint
    if args.stager is True:
        if args.hybnic is None:
            print('--stager required --hybnic')
            sys.exit(1)

    ## Tap constraints
    if args.t is False:
        if args.wired is True:
            print('--wired requires -t')
            sys.exit(1)

    ## Tap mode
    if args.t is True:
        print('Running in tap mode')
        Tap()
        subprocess.check_call('ifconfig tap0 up', shell = True)
        time.sleep(2)
        Tap(tapNum = 1)
        subprocess.check_call('ifconfig tap1 up', shell = True)
        time.sleep(2)
        Tap(tapNum = 2)
        subprocess.check_call('ifconfig tap2 up', shell = True)

        ## Queue handler
        hd = Handler(args)


        """
        Listener and stager can be svr clt model
        """


        # ## Listener
        # hd.LR = Queue()
        # LRET.theThread = hd.listener
        # lret = LRET(jobList = hd.LR, nThread = 1)
        # LISTENER.theThread = lrWork
        # LRBG = LISTENER()
        # LRBG.easyLaunch()
        # srcLr, srcEt, srcBg  = hd.queueGen('listener')
        # time.sleep(2)
        sendp(Ether(IP()/TCP()), iface = 'tap0', count = 2)
        time.sleep(2)

        ## Stager
        if args.stager is True:
            if args.hybip is not None:
                if args.hybport is not None:
                    hd.SR = Queue()
                    SRET.theThread = hd.stager
                    sret = SRET(jobList = hd.SR, nThread = 1)
                    STAGER.theThread = srWork
                    SRBG = STAGER()
                    SRBG.easyLaunch()
                    srcIILr, srcIIEt, srcIIBg  = hd.queueGen('stager')
                    time.sleep(2)
                    sendp(Ether(IP()/TCP()), iface = 'tap1', count = 2)         ### HARDCODE
                    time.sleep(2)
                else:
                    print('--stager requires --hybip and --hybport')
                    sys.exit(1)

        # ## Repeater
        # if args.repeater is True:
        #     hd.RR = Queue()
        #     RRET.theThread = hd.repeater
        #     rret = RRET(jobList = hd.RR, nThread = 1)
        #     REPEATER.theThread = rrWork
        #     RRBG = REPEATER()
        #     RRBG.easyLaunch()
        #     srcIIILr, srcIIIEt, srcIIIBg  = hd.queueGen('repeater')
        #     time.sleep(2)
        #     sendp(Ether(IP()/TCP()), iface = 'tap2', count = 2)

    ## Server
    if args.s is True:
        print('Running in server mode')
        if args.wired is False:
            print('Serving wireless')
        else:
            print('Serving wired')

        ### This needs to be backgrounded so hybrid model works below it

        ## Background virtual sniffing
        sh2 = Shared(args, box)
        SERVER.theThread = sh2.serverSniff
        srv = SERVER()
        srv.easyLaunch()

        ## Background receiption sniffing
        # sendp(packet[Raw].load, iface = self.args.snfnic, verbose = False)

        # x=self.box.decrypt(packet[Raw].load)
        # decrypted = RadioTap(binascii.unhexlify(x)) <<<<<<<<  Most likely need to still unhexlify the below box
        # sendp(decrypted, iface = self.args.snfnic, verbose = False)

        # sendp(RadioTap(x[Raw].load), iface = self.args.snfnic, verbose = False)

        if args.t is True:
            print('Running in server tap mode')

            ### Move this later
            if args.snfnic is None:
                print('--snfnic required with -s and -t usage')
                sys.exit(1)


            ### Need to closure the prns
            ### Go with "only process if decryption works" built into the Security model


            if args.weak is False:
                print('only --weak supported during implementation of server tap mode')
                sys.exit(1)
                sniff(iface = args.snfnic,
                      prn = lambda x: sendp(box.decrypt(x), iface = args.monnic, verbose = args.verbose),
                      lfilter = lambda y: y.haslayer(UDP) and y[UDP].dport == args.hybport,
                      store = 0)
            else:
                try:
                    sniff(iface = args.snfnic,
                          # prn = lambda x: x.summary() and sendp(x, iface = args.monnic, verbose = True),
                          prn = lambda x: x.summary(),
                          # lfilter = lambda y: y.dport == args.hybport,
                          filter = args.hybport,
                          # lfilter = lambda y: y.haslayer(UDP) and y[UDP].dport == args.hybport,
                          store = 0)
                except Exception as E:
                    print(E)

        ## Implement when ^ is closured
        # ## Show user final logic
        # print(args)
        # if args.debug is False:
        #     while True:
        #         time.sleep(10000)

    ## Client
    if args.c is True:
        print('Running in client mode')

        if args.snfnic is None:
            print('--snfnic required with -c')
            sys.exit(1)

        ## Create virtual wlan device
        if args.wired is False:
            os.system('modprobe mac80211_hwsim radios=2 > /dev/null')
            time.sleep(2)
            os.system('airmon-ng start {0} > /dev/null'.format(args.snfnic.replace('mon', '')))
            time.sleep(3)

        ## Background virtual sniffing
        sh = Shared(args, box)
        Backgrounder.theThread = sh.clientSniff
        bg = Backgrounder()
        bg.easyLaunch()

        ## Show user final logic
        print(args)
        if args.debug is False:
            while True:
                time.sleep(10000)
