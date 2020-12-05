from select import select
from threading import Thread, Event
from scapy.all import conf, ETH_P_ALL, MTU, plist

# Stop sniff() asynchronously
# Source: https://github.com/secdev/scapy/issues/989#issuecomment-380044430

def sniff(store=False, prn=None, lfilter=None,
          stop_event=None, refresh=.1, *args, **kwargs):
    """Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args)

  store: wether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)
stop_event: Event that stops the function when set
refresh: check stop_event.set() every refresh seconds
    """
    s = conf.L2listen(type=ETH_P_ALL, *args, **kwargs)
    lst = []
    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            sel = select([s], [], [], refresh)
            if s in sel[0]:
                p = s.recv(MTU)
                if p is None:
                    break
                if lfilter and not lfilter(p):
                    continue
                if store:
                    lst.append(p)
                if prn:
                    r = prn(p)
                    if r is not None:
                        print(r)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

    return plist.PacketList(lst, "Sniffed")

"""
Single thread rapper for asynchronous packet sniffer
"""
class Sniffer(object):

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.running = False
        self.thread = None
        self.sniff_data = None
        self.stop_event = Event()

    def _sniff(self, store=False, prn=None, lfilter=None,
             refresh=.1, *args, **kwargs):
        s = conf.L2listen(type=ETH_P_ALL, *args, **kwargs)
        lst = []
        self.running = True
        try:
            while True:
                if self.stop_event and self.stop_event.is_set():
                    break
                sel = select([s], [], [], refresh)
                if s in sel[0]:
                    p = s.recv(MTU)
                    if p is None:
                        break
                    if lfilter and not lfilter(p):
                        continue
                    if store:
                        lst.append(p)
                    if prn:
                        r = prn(p)
                        if r is not None:
                            print(r)
        except KeyboardInterrupt:
            pass
        finally:
            s.close()

        self.sniff_data = plist.PacketList(lst, "Sniffed")

    #debug purpose
    def fetch_sniff_data(self):
        return self.sniff_data

    def start(self):
        self.thread = Thread(
            target=self._sniff,
            args=self.args,
            kwargs=self.kwargs
        )
        self.thread.setDaemon(True)
        self.thread.start()

    def stop(self, join=True):
        if self.running:
            self.stop_event.set()
            if join:
                self.thread.join()
                self.running = False
                return self.sniff_data
        else:
            raise Exception("Not started !")
