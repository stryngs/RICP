#!/usr/bin/python3

"""
A protocol for transmitting the 0s and 1s of any interface over UDP in such a
way as that the client node sees the interface as physically local by way of
mac80211_hwsim for wireless and a tap interface for wired.

References
https://www.suse.com/c/creating-virtual-wlan-interfaces/
https://github.com/secdev/scapy/issues/724#
"""

import argparse
import binascii
import os
import psutil
import random
import signal
import sys
import time
from easyThread import Backgrounder
from queue import Queue
from scapy.all import *
# from scapy.sendrecv import __gen_send as gs

class Handler(object):
    """tap interface handler"""
    __slots__ = ['LR',
                 'SR',
                 'RR',
                 'args',
                 'dport',
                 'dstip',
                 'sport',
                 'srcip']

    def __init__(self, args):
        self.args = args
        if self.args.dstport is None:
            self.args.dstport = random.randint(0, 65535)
        if self.args.dstip is None:
            self.args.dstip = '127.0.0.1'
        if self.args.srcport is None:
            self.args.srcport = random.randint(0, 65535)
        if self.args.srcip is None:
            self.args.srcip = '127.0.01'

        # self.injSocket = conf.L2socket(iface = interface)
        # self.injSocket = conf.L3socket(iface = interface)

    def listener(self, work):
        """Listens for inbound on tap0 and then sends to the stager"""
        while True:
            l = self.LR.get()
            if l is not None:
                print('Listener received')
                print(l.summary())
                try:
                    sendp(l, iface = 'tap1', verbose = 0)
                except:
                    pass
                self.LR.task_done()

    def stager(self, work):
        """Listens for inbound on tap1 and then sends to the repeater"""
        while True:
            s = self.SR.get()
            if s is not None:
                print('Stager received')
                print(s.summary())
                try:
                    sendp(s, iface = 'tap2', verbose = 0)
                except:
                    pass
                self.SR.task_done()

    def repeater(self, work):
        """Listens for inbound on tap2 and then sends to the destination"""
        # while True:
        #     r = self.RR.get()
        #     if r is not None:
        #         print('Repeater received')
        #         print(r.summary())
        #         self.RR.task_done()
        while True:
            r = self.RR.get()
            ### Can enter here too for NIC control via the client.

            if r is not None:
                print('Repeater received')
                print(r.summary())
                ### This is our entry point for NIC control via the client.
                self.RR.task_done()


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
                sniff(iface = 'tap0', prn = lambda x: lr.LR.put(x))

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
                sniff(iface = 'tap1', prn = lambda x: sr.SR.put(x))

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
                sniff(iface = 'tap2', prn = lambda x: rr.RR.put(x))

            ## Add our function to Backgrounder
            REPEATERII.theThread = tap2
            rrBgII = REPEATERII()

            ## Start the work
            rrBgII.easyLaunch()
            return rr, rrEt, rrBg


class Shared(object):
    __slots__ = ['args']

    def __init__(self, args):
        self.args = args

    def clientSniff(self):
        """Copy from the monitoring NIC and inject to the sniff NIC"""
        if self.args.wired is False:
            sniff(iface = self.args.monnic,
                  prn = lambda x: sendp(RadioTap(x[Raw].load),
                                        iface = self.args.snfnic,
                                        verbose = 0),
                  store = 0,
                  filter = self.args.bpf)
        else:
            try:
                sniff(iface = self.args.monnic,
                      prn = lambda x: sendp(Ether(x.load),
                                            iface = self.args.snfnic,
                                            verbose = 0),
                      store = 0,
                      filter = self.args.bpf)
            except Exception as E:
                print(E)


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
    parser.add_argument('--injnic', help = 'injection nic')
    parser.add_argument('--monnic', help = 'monitoring nic', required = True)
    parser.add_argument('--repeater', action = 'store_true', help = 'Setup the repeater for tap mode')
    parser.add_argument('--snfnic', help = 'sniffing nic')
    parser.add_argument('--srcmac', help = 'source mac')
    parser.add_argument('--srcport', help = 'source port', required = True)
    parser.add_argument('--srcip', help = 'source ip', required = True)
    parser.add_argument('--stager', action = 'store_true', help = 'Setup the stager for tap mode')
    parser.add_argument('--wired', action = 'store_true', help = 'wired mode, requires -t')
    parser.add_argument('-c', action = 'store_true', help = 'run as client')
    parser.add_argument('-s', action = 'store_true', help = 'run as server')
    parser.add_argument('-t', action = 'store_true', help = 'tap mode')
    args = parser.parse_args()

    ## ADD SIGNAL HANDLER
    signal_handler = crtlC()
    signal.signal(signal.SIGINT, signal_handler)

    ## Tap constraints
    if args.t is False:
        if args.wired is True:
            print('--wired requires -t')
            sys.exit(1)

    ## Tap mode
    if args.t is True:
        from easyThread import Backgrounder as LISTENER
        from easyThread import Backgrounder as LISTENERII
        from easyThread import EasyThread as LRET
        from easyThread import Backgrounder as STAGER
        from easyThread import Backgrounder as STAGERII
        from easyThread import EasyThread as SRET
        from easyThread import Backgrounder as REPEATER
        from easyThread import Backgrounder as REPEATERII
        from easyThread import EasyThread as RRET
        from pyDot11 import *
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

        ## Listener
        hd.LR = Queue()
        LRET.theThread = hd.listener
        lret = LRET(jobList = hd.LR, nThread = 1)
        LISTENER.theThread = lrWork
        LRBG = LISTENER()
        LRBG.easyLaunch()
        srcLr, srcEt, srcBg  = hd.queueGen('listener')
        time.sleep(2)
        sendp(Ether(IP()/TCP()), iface = 'tap0', count = 2)
        time.sleep(2)

        ## Stager
        if args.stager is True:
            hd.SR = Queue()
            SRET.theThread = hd.stager
            sret = SRET(jobList = hd.SR, nThread = 1)
            STAGER.theThread = srWork
            SRBG = STAGER()
            SRBG.easyLaunch()
            srcIILr, srcIIEt, srcIIBg  = hd.queueGen('stager')
            time.sleep(2)
            sendp(Ether(IP()/TCP()), iface = 'tap1', count = 2)
            time.sleep(2)

        ## Repeater
        if args.repeater:
            hd.RR = Queue()
            RRET.theThread = hd.repeater
            rret = RRET(jobList = hd.RR, nThread = 1)
            REPEATER.theThread = rrWork
            RRBG = REPEATER()
            RRBG.easyLaunch()
            srcIIILr, srcIIIEt, srcIIIBg  = hd.queueGen('repeater')
            time.sleep(2)
            sendp(Ether(IP()/TCP()), iface = 'tap2', count = 2)


    ## Raw BPF
    if args.bpf is None:
        if args.c is True:

            ### Clean this up more
            args.bpf = 'udp port {0} and ((src {1} and dst {2}) or (dst {1} and src {2}))'.format(args.srcport, args.srcip, args.dstip)

    ## Server
    if args.s is True:
        sniff(iface = args.monnic,
              prn = lambda x: send(IP(src = args.srcip, dst = args.dstip)/\
                                   UDP(sport = int(args.srcport), dport = int(args.dstport))/\
                                   Raw(load = x),
                                   verbose = 0),
              store = 0,
              lfilter = lambda y: y.summary(),
              filter = args.bpf)

    ## Client
    if args.c is True:
        if args.injnic is None:
            print('--injnic required with -c')
            sys.exit(1)

        if args.snfnic is None:
            print('--snfnic required with -c')
            sys.exit(1)

        ## Create virtual wlan device
        os.system('modprobe mac80211_hwsim radios=1 > /dev/null')
        time.sleep(2)
        os.system('airmon-ng start {0} > /dev/null'.format(args.snfnic.replace('mon', '')))
        time.sleep(3)

        ## Background virtual sniffing
        sh = Shared(args)
        Backgrounder.theThread = sh.clientSniff
        bg = Backgrounder()
        bg.easyLaunch()

        ## Show user final logic
        print(args)
        if args.debug is False:
            while True:
                time.sleep(10000)
