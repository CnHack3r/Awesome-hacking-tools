import platform
import time
from plugins.common.common import allfile
import threading

class host_infomation:
    def __init__(self):
        self.hostname = ""
        self.version = ""
        self.time = ""
        self.host_info()

    def host_info(self):
        self.hostname = platform.node()
        self.version = platform.platform()
        self.time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    def run(self):
        print(u'\n\033[1;33mHost Information\033[0m')
        print(u'  Host name   : %s' % self.hostname)
        print(u'  Host version: %s' % self.version)
        print(u'  Host time   : %s' % self.time)