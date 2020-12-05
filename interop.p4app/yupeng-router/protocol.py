from threading import Thread, Event

############################################
# Helper class functions
############################################

class ProtocolWorker(object):
    def __init__(self, switch, timeout=60):
        self.switch = switch
        self.running = False
        self.thread = None
        self.stop_event = Event()
        self.timeout = timeout

    def start(self, **kwargs):
        self.thread = Thread(target=self._run, kwargs=kwargs)
        self.thread.setDaemon(True)
        self.thread.start()

    def stop(self):
        if self.running:
            self.stop_event.set()
            if self.thread:
                self.thread.join()
                self.running = False
        else:
            #FIXME fix this exception message
            raise Exception("The worker is not running!")

"""
Ip/Hex helper function
"""

def hex_to_ip(ip_hex):
    origin_ip_hex = ip_hex
    numbers = []
    result = ""
    for i in range(4):
        numbers.append(str(ip_hex % 256))
        ip_hex /= 256
    for i in range(4):
        result = result + numbers.pop()
        if i != 3:
            result = result + "."
    if(result == "10.1.0.101"):
        print("IP hex:::::::    " + str(origin_ip_hex))
        print("IP result:::::::    " + str(result))
    return result

def ip_to_hex(ip):
    numbers = [int(x) for x in ip.split('.')]
    result = 0
    for i in range(4):
        result = result * 256 + numbers[i]
    return result


# Calculate subnet and prefix length
def get_prefix(subnet, netmask):
    mask = ip_to_hex(netmask)
    subnet = hex_to_ip(ip_to_hex(subnet) & mask)
    prefix_length = 0
    while mask:
        mask = mask << 1
        if mask & 0x100000000:
            prefix_length += 1
        mask &= 0xffffffff
    return '%s/%d' % (subnet, prefix_length)
