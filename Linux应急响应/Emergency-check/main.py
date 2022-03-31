from plugins.History_check import History_check
from plugins.User_check import User_check
from plugins.Backdoor_check import Backdoor_check
from plugins.Config_check import Config_check
from plugins.Log_check import Log_check
from plugins.Proc_check import Proc_check
from pre_check import host_infomation
from plugins.common.common import allfile
from conf.conf import init
import threading,time

def begin():
    print("""\033[1;36m
    ====================================
    ==    Emergency Security Check    ==
    ====================================

    [+]Author :ChrisKaliX
    [+]Version:Test
    \033[0m""")

def check_all():
    def check(method):
        c = method()
        c.run()
    check(host_infomation)
    check(History_check)
    check(User_check)
    check(Backdoor_check)
    check(Config_check)
    check(Log_check)
    check(Proc_check)

start = time.time()
t=threading.Thread(target=init.getallfile)
t.start()

begin()
check_all()
end = time.time()
print(end-start)
