from plugins.common.common import printf,strings,align
from plugins.common.Analysis import check_all,getfile,analysis
import os,time,sys,json,re
import platform
from conf.conf import *
import stat

class Backdoor_check:
    def __init__(self):
        self.name = "Backdoor Security Check"
        self.suspicious_backdoor = []

    def check_backdoor(self,tag):
        def check_tag(filename, tag):
            if not os.path.exists(filename):
                return False
            if os.path.isdir(filename):
                return False
            for line in open(filename, 'r').readlines():
                line = line.replace("\n", "")
                if line[0] == "#":
                    continue
                if "export " + tag in line:
                    return True
            return False
        try:
            files = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/root/.tcshrc',
                     '/etc/bashrc', '/etc/profile', '/etc/profile.d/', '/etc/csh.login', '/etc/csh.cshrc']
            home_files = ['/.bashrc', '/.bash_profile',
                          '/.tcshrc', '/.cshrc', '/.tcshrc']

            for sub_dir in os.listdir("/home/"):
                for home_file in home_files:
                    sub_file = os.path.join("%s%s%s" %
                                            ("/home/", sub_dir, home_file))
                    info = check_tag(sub_file, tag)
                    if info:
                        return [sub_file, tag]
                    else:
                        return False

            for sub_file in files:
                if os.path.isdir(sub_file):
                    for sub_file in getfile(sub_file):
                        info = check_tag(sub_file, tag)
                        if info:
                            return [sub_file, tag]
                        else:
                            return False
                else:
                    info = check_tag(sub_file, tag)
                    if info:
                        return [sub_file, tag]
                    else:
                        return False
        except:
            return False

    def LD_PRELOAD_check(self):
        ini = len(self.suspicious_backdoor)
        result = self.check_backdoor("LD_PRELOAD")
        if result:self.suspicious_backdoor.append(result)
        end = len(self.suspicious_backdoor)
        return True if end == ini else False
    
    def LD_AOUT_PRELOAD_check(self):
        ini = len(self.suspicious_backdoor)
        result = self.check_backdoor("LD_AOUT_PRELOAD")
        if result:self.suspicious_backdoor.append(result)
        end = len(self.suspicious_backdoor)
        return True if end == ini else False
    
    def LD_ELF_PRELOAD_check(self):
        ini = len(self.suspicious_backdoor)
        result = self.check_backdoor("LD_ELF_PRELOAD")
        if result:self.suspicious_backdoor.append(result)
        end = len(self.suspicious_backdoor)
        return True if end == ini else False

    def LD_LIBRARY_PATH_check(self):
        ini = len(self.suspicious_backdoor)
        result = self.check_backdoor("LD_LIBRARY_PATH")
        if result:self.suspicious_backdoor.append(result)
        end = len(self.suspicious_backdoor)
        return True if end == ini else False

    def PROMPT_COMMAND_check(self):
        ini = len(self.suspicious_backdoor)
        result = self.check_backdoor("PROMPT_COMMAND")
        if result:self.suspicious_backdoor.append(result)
        end = len(self.suspicious_backdoor)
        return True if end == ini else False

    def export_check(self):
        ini = len(self.suspicious_backdoor)
        result = self.check_backdoor("PATH")
        if result:self.suspicious_backdoor.append(result)
        end = len(self.suspicious_backdoor)
        return True if end == ini else False
    
    ######
    def ld_so_preload(self):
        try:
            ##centos
            ini = len(self.suspicious_backdoor)
            if os.path.exists("/etc/ld.so.preload"):
                for line in open("/etc/ld.so.preload",'r').readlines():
                    line = line.replace("\n","")
                    if line[0] == "#":continue
                    if line[-3:] == ".so":
                        self.suspicious_backdoor.append(["/etc/ld.so.preload",line])
                        return False
                    else:
                        result = check_all.check_shell(line)
                        self.suspicious_backdoor.append(["/etc/ld.so.preload",line])
                        return (False if result else True)

            ##Ubuntu found no ld.so.preload. Only ld.so.conf was found.
            else:return True
        except:
            return True

    #check file
    def cron_check(self):
        file_list = []
        def file_exsit(content):
            try:
                a = re.compile(r"\/((\w|\.)+?\/)+(\w|\.)+")
                return a.search(content)[0]
            except:
                return False
        try:
            ini = len(self.suspicious_backdoor)
            cron_list = ['/var/spool/cron/', '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.weekly/','/etc/cron.hourly/', '/etc/cron.monthly/']
            for cron in cron_list:
                for sub_file in getfile(cron):
                    if not os.path.exists(sub_file):continue
                    if os.path.isdir(sub_file):continue
                    for line in open(sub_file,'r').readlines():
                        line = line.replace("\n", "")
                        if len(line) < 3:continue
                        if line[0] == "#":continue
                        content = check_all.check_shell(line)
                        if content:self.suspicious_backdoor.append([cron,line])
                        in_file = file_exsit(line)
                        if in_file in file_list:continue
                        else:file_list.append(in_file)

                        ##if file in crontab,check the file

                        if in_file:
                            try:
                                for i in open(in_file,'r').readlines():
                                    i = i.replace("\n","")
                                    res = check_all.check_shell(i)
                                    if res:self.suspicious_backdoor.append([sub_file,i])
                            except:
                                pass
            end = len(self.suspicious_backdoor)
            return True if end == ini else False
        except:
            return True
    
    # Check counts of ssh connection (which I think is coincide?)
    #
    # 2020-03-16
    # A kind of ssh login way: `ssh -T username@host /bin/bash -i`
    # And use last, who, w can't detect the ssh login.
    # Why?
    #   -T means no terminal, it interacts with bash.
    # How to detect?
    #   For the ssh check part, it really can not detect this login.
    #   The shell detect part, however, which go through all the file,
    #   can detect the `/bin/bash -i` command. So basically it can be
    #   checked by my script.
    #
    def SSH_check(self):
        ini = len(self.suspicious_backdoor)
        def trans(content):
            return int(content,16)
        try:
            #find all in proc file
            regex = re.compile(r"^\d+$")
            inode_to_pid = {}
            for pid_str in os.listdir("/proc/"):
                if regex.match(pid_str):
                    fds = os.listdir("/proc/%s/fd"%pid_str)
                    pid = int(pid_str)
                    for fd in fds:
                        try:
                            link = os.readlink("/proc/%s/fd/%s"%(pid_str,fd))
                        except:
                            continue
                        if link.startswith("socket:"):
                            inode_to_pid[int(link[8:-1])] = pid

            pid_list = []
            for sub_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
                with open(sub_file,'r') as the_file:
                    iterfile = iter(the_file)
                    next(iterfile)
                    for line in iterfile:
                        line = line.replace("\n", "").split(" ")
                        while '' in line:line.remove('')
                        localport = trans(line[1].split(":")[1])
                        if localport == 22:continue
                        inode = int(line[9])
                        pid = inode_to_pid[inode]
                        if pid not in pid_list:
                            pid_list.append(pid)
            
            results = []
            #check pid
            for pid in pid_list:
                pid = str(pid)
                if os.path.exists("/proc/%s/exe" % pid):
                    if 'sshd' in os.readlink("/proc/%s/exe" % pid):
                        results.append(["/proc/%s/exe" % pid, "More than one SSH connection"])
            
            #If one only,It's gonna be my ssh
            if len(results) < 2:
                return True
            
            for result in results:
                self.suspicious_backdoor.append(result)
            end = len(self.suspicious_backdoor)
            return True if end == ini else False
        except:
            return True
    
    def SSH_softlink(self):
        try:
            if not os.path.islink("/usr/sbin/sshd"):
                return True
            else:
                self.suspicious_backdoor.append(["/usr/sbin/sshd","softlink"])
                return False
        except:
            return True

    # Check ssh wrapper
    def SSH_wrapper_check(self):
        def ELF_check(path): 
            data = open(path, "rb").read(8).hex()
            if data == "7f454c4602010100":
                return True
            else:
                return False
        result = ELF_check("/usr/sbin/sshd")
        if result:
            return True
        else:
            self.suspicious_backdoor.append(["/usr/sbin/sshd","Not elf"])
            return False

    def inted_check(self):
        try:
            ini = len(self.suspicious_backdoor)
            if not os.path.exists("/etc/inetd.conf"):return True
            with open("/etc/inetd.conf") as sub_file:
                for line in sub_file:
                    content = check_all.check_shell(line)
                    if content:
                        self.suspicious_backdoor.append(["/etc/inetd.conf", line])
            end = len(self.suspicious_backdoor)
            return True if end == ini else False
        except:
            return True

    def xinetd_check(self):
        try:
            ini = len(self.suspicious_backdoor)
            if not os.path.exists("/etc/xinetd.conf"):return True
            for sub_file in os.listdir("/etc/xinetd.conf"):
                with open(os.path.join("%s%s" % ("/etc/xinetd.conf", sub_file))) as files:
                    for line in files:
                        content = check_all.check_shell(line)
                        if content:self.suspicious_backdoor.append()
            end = len(self.suspicious_backdoor)
            return True if end == ini else False
        except:
            return True

    ## Run_all_the_file,one time
    ## int(str(pri))....can be better
    ## setuid and check can be together

    #
    # See, I think I found a big problem.
    # I should never run check all file before it's done.
    #

    def setuid_check(self):
        plat = platform.platform()
        under_check = []

        # Try to find out more elegant way.
        while not init._status:
            time.sleep(0.1)
        for sub_file in init.file_list:
            try:
                if not os.path.exists:continue
                if ((len(sub_file)>5) and (sub_file[:5] == "/proc")):continue
                mode = os.stat(sub_file).st_mode
                if not stat.S_ISREG(mode):continue
                pri = int(oct(mode)[-4:])
                if ((pri > 4000) and ((int(str(pri)[-1]) % 2) or (int(str(pri)[-2]) % 2))):
                    under_check.append(sub_file)
            except:
                pass

        sus_list = ['pam_timestamp_check', 'unix_chkpwd', 'ping', 'mount', 'bin/su', 'pt_chown', 'ssh-keysign', 'at', 'passwd', 'chsh', 'crontab', 'chfn', 'usernetctl', 'staprun','newgrp','ksu',
                    'chage', 'dhcp', 'helper', 'pkexec', '/usr/bin/top', 'Xorg', 'nvidia-modprobe', 'quota', 'login', 'security_authtrampoline', 'authopen', 'traceroute6', 'traceroute', '/usr/bin/ps',
                    'mail', 'exim', 'smtp', 'rcp', 'rsh', 'vmware-user', 'pppd', 'runq', 'ntfs-3g', 'newaliases', 'sg', 'bwrap', 'kismet_capture', 'chrome-sandbox', 'dmcrypt-get-device', 'kismet_cap_']
        if "Ubuntu" in plat:
            sus_list.extend(["ubuntu-core-launcher","/snap/core", "snap-confine"])
        result = under_check[:]
        for i in under_check:
            for j in sus_list:
                if j in i:
                    result.remove(i)
                    break
        for i in result:
            self.suspicious_backdoor.append([i,"setuid"])  
        return True if result == [] else False
    
    def chmod_777_check(self):
        ini = len(self.suspicious_backdoor)
        while not init._status:
            time.sleep(0.1)
        for list1 in [init.file_list,init.dir_list]:
            for sub_file in list1:
                try:
                    if (sub_file[:5] == "/proc"):continue
                    if not os.path.exists(sub_file):continue
                    mode = os.stat(sub_file).st_mode
                    if not stat.S_ISREG(mode):continue
                    if stat.S_ISSOCK(mode):continue
                    if int(oct(mode)[-3:]) == 777:
                        if '/gems/' in sub_file:continue
                        self.suspicious_backdoor.append([sub_file,"privileges 777"])
                except:
                    continue
        end = len(self.suspicious_backdoor)
        return True if end == ini else False

    def startup_check(self):
        try:
            ini = len(self.suspicious_backdoor)
            init_path = ['/etc/init.d/', '/etc/rc.d/', '/etc/rc.local', '/usr/local/etc/rc.d',
                      '/usr/local/etc/rc.local', '/etc/conf.d/local.start', '/etc/inittab', '/etc/systemd/system']
            for path in init_path:
                if not os.path.exists(path):continue
                if os.path.isfile(path):
                    result = analysis.checkfile(path)
                    if type(result) == list:
                        for i in result:
                            self.suspicious_backdoor.append(i)
                    continue
                for sub_file in getfile(path):
                    result = analysis.checkfile(sub_file)
                    if type(result) == list:
                        for i in result:
                            self.suspicious_backdoor.append(i)
            end = len(self.suspicious_backdoor)
            return True if end == ini else False
        except:
            return True
        
    def alias_check(self):
        def alias_file_check(files):
            syscmds = ['ps','strings','netstat','find','echo','iptables','lastlog','who','ifconfig','ssh']
            try:
                with open(files) as sub_file:
                    for line in sub_file:
                        if len(line) < 5: continue
                        if line[:5] == 'alias':
                            for syscmd in syscmds:
                                if 'alias' + syscmd + '=' in line:
                                    return False
                                if (('alias' in line) and ('strace' in line)):
                                    return False
                return True
            except:
                return True
        
        # Datetime: 2020-03-13
        # Diffrence between /etc/profile & /etc/profile.d/
        # 
        # /etc/profile is called only when login shell launchs
        # /etc/profile.d/ is mainly for other application
        # 
        # So i reckon those should be detected as well

        files = ['/root/.bashrc', '/root/.bash_profile',
                 '/etc/bashrc', '/etc/profile','/etc/profile.d/']
        try:
            ini = len(self.suspicious_backdoor)
            for dirs in os.listdir("/home/"):
                path = os.path.join('%s%s%s' % ('/home/', dirs, '/.bashrc'))
                if os.path.exists(path):
                    result = alias_file_check(path)
                    if not result:
                        self.suspicious_backdoor.append([path,"Alias"])
                path = os.path.join('%s%s%s' % ('/home/',dirs,'/.bash_profile'))
                if os.path.exists(path):
                    result = alias_file_check(path)
                    if not result:
                        self.suspicious_backdoor.append([path,"Alias"])
            for sub_file in files:
                if os.path.exists(sub_file):
                    if os.path.isdir(sub_file):
                        file_list = [os.path.join(sub_file,filename) for filename in sub_file]
                        for filename in file_list:
                            result = alias_file_check(filename)
                            if not result:
                                self.suspicious_backdoor.append([path, "Alias"])
                    result = alias_file_check(sub_file)
                    if not result:
                        self.suspicious_backdoor.append([path,"Alias"])
            end = len(self.suspicious_backdoor)
            return True if end == ini else False
        except:
            return True

    ## openssh version check
    def openssh_check(self):
        lines = strings("/usr/sbin/sshd")
        ini = len(self.suspicious_backdoor)
        def email_valid(line):
            result = re.finditer(r'([\w\.-]+?)@([\w\.-]+?)(\.[\w\.]+)', line)
            return_list = []
            try:
                while True:
                    return_list.append(next(result).group())
            except StopIteration:
                return return_list
        def ip_valid(line):
            result = re.finditer("((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)",line)
            return_list = []
            try:
                while True:
                    return_list.append(next(result).group())
            except StopIteration:
                return return_list
        for line in lines:
            try:
                line = next(lines)
                for i in email_valid(line):
                    if ((i[-12:] == '@openssh.com') or (i == "rijndael-cbc@lysator.liu.se")):continue
                    if (i[-11:] == '@libssh.org'):continue
                    if ('@tinyssh.org' in i):continue
                    self.suspicious_backdoor.append(["/usr/sbin/sshd", ''.join(i)])
                for i in ip_valid(line):
                    if (re.match('^(127\\.0\\.0\\.1)|(localhost)|(0.0.0.0)|(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(172\\.((1[6-9])|(2\\d)|(3[01]))\\.\\d{1,3}\\.\\d{1,3})|(192\\.168\\.\\d{1,3}\\.\\d{1,3})$',i)):continue
                    self.suspicious_backdoor.append(["/usr/sbin/sshd", ''.join(i)])
            except:
                pass
        end = len(self.suspicious_backdoor)
        return True if end == ini else False

    ##/etc/fstab
    ##untested undercheck
    def fstab_check(self):
        if os.path.exists("/etc/fstab"):
            if int(oct(os.stat("/etc/fstab").st_mode)[-3:]) > 664:
                self.suspicious_backdoor.append(["/etc/fstab","privileges not 664"])
                return False
            else:
                return True
        else:
            return True
    
    ## setuid and setgid has it's own white list.
    ## It can be bypass
    def setgid_check(self):
        plat = platform.platform()
        under_check = []
        ini = len(self.suspicious_backdoor)
        for sub_file in init.file_list:
            try:
                if sub_file[:5] == "/proc":
                    continue
                mode = os.stat(sub_file).st_mode
                if not stat.S_ISREG(mode):
                    continue
                pri = int(oct(mode)[-4:])
                if ((3000> pri > 2000) and ((int(str(pri)[-1]) % 2) or (int(str(pri)[-2]) % 2))):
                    under_check.append(sub_file)
            except:
                continue
        
        #Add if u need
        sus_list = ["docker","camel-lock-helper", "ssh-agent", "utempter", "chage", "cons.saver","crontab", "unix_chkpwd", "dotlock", "locate", "write", "wall", "expiry","postdrop","postqueue","netreport","cgexec","cgclassify"]
        if "Ubuntu" in plat:
            sus_list.extend(["/snap/core", "pam_extrausers_chkpwd"])
        result = under_check[:]
        for i in under_check:
            for j in sus_list:
                if j in i:
                    result.remove(i)
                    break
        for i in result:
            self.suspicious_backdoor.append([i,"setgid"])
        end = len(self.suspicious_backdoor)
        return True if end == ini else False

    # PAM check(not good and unfinished)
    def pam_check(self):
        ini = len(self.suspicious_backdoor)

        # Check the /etc/ssh/sshd_config file, if PAM is enabled, it should be suspicious
        # Because it default off on my server...(So it maybe wrong sometime)

        if os.path.exists("/etc/ssh/sshd_config"):
            with open("/etc/ssh/sshd_config","r") as f:
                for line in f.readlines():
                    if line.startswith("#"):
                        continue
                    if ("UsePAM" in line.strip("\n")) and ("yes" in line.strip("\n")):
                        self.suspicious_backdoor.append(
                            ["/etc/ssh/sshd_config", "PAM enabled"])
        
        #
        # In PAM, file maybe replace with a malicious one, my first thought was to compare
        # all md5 hashes, but find out hashes of all versions and platforms maybe a little
        # bit tricky for me. So if u got an better idea, please leave it in issue, thanks!
        # 

        #
        # Now the paper that I read. I write this one for check. It's silly, but still a
        # kind of check.( :( better than nothing )
        # 

        # pam_list = ["/etc/pam.d/sshd", "/etc/pam.d/sudo","/etc/pam.d/su","/etc/pam.d/passwd"]
        # so_file_list = list
        # for pamfile in pam_list:
        #     if not os.path.exists(pamfile):continue

        #     # Open all pam file, and find out the pam .. so file. Check the date they changed
        #     # ...I know it maybe some stupid, I'll try to figure out a better approach. 
        #     with open(pamfile,"r") as f:
        #         for line in f.readlines():
        #             if line.startswith("#"):continue
        #             if line.startswith("auth") and ("require" in line):
        #                 so_file = re.findall(r"pam.*?\.so", line)
        #                 if not len(so_file):
        #                     self.suspicious_backdoor.append([pamfile,"pam ... so not find"])
        #                 else:
        #                     so_file_list.append(so_file[0])

        # #
        # # If .so file was found in the file
        # #

        end = len(self.suspicious_backdoor)
        return True if end == ini else False

    # By the way, I'm thinking of webshell these days. I am willing to write a simple one,
    # Because it can be tricky if you want a good one. I read GScan, it use yaml and regex
    # to do the check. I don't want use yaml for it's inconvenience of upgrading.

    def run(self):
        print(u'\n\033[1;33m%s\033[0m' % self.name)
        print(u'  %s%s' % (align("[1]LD_PRELOAD check"),printf(self.LD_PRELOAD_check())))
        print(u'  %s%s' % (align("[2]LD_AOUT_PRELOAD check"), printf(self.LD_AOUT_PRELOAD_check())))
        print(u'  %s%s' % (align("[3]LD_ELF_PRELOAD check"),printf(self.LD_ELF_PRELOAD_check())))
        print(u'  %s%s' % (align("[4]LD_LIBRARY_PATH check"),printf(self.LD_LIBRARY_PATH_check())))
        print(u'  %s%s' % (align("[5]PROMPT_COMMAND check"),printf(self.PROMPT_COMMAND_check())))
        print(u'  %s%s' % (align("[6]Export check"),printf(self.export_check())))
        print(u'  %s%s' % (align("[7]LD_SO_PRELOAD check"),printf(self.ld_so_preload())))
        print(u'  %s%s' % (align("[8]Cron check"),printf(self.cron_check())))
        print(u'  %s%s' % (align("[9]SSH backdoor check"),printf(self.SSH_check())))
        print(u'  %s%s' % (align("[10]SSH_softlink check"),printf(self.SSH_softlink())))
        print(u'  %s%s' % (align("[11]SSH wrapper check"),printf(self.SSH_wrapper_check())))
        print(u'  %s%s' % (align("[12]Inted check"), printf(self.inted_check())))
        print(u'  %s%s' % (align("[13]Xinted check"),printf(self.xinetd_check())))
        print(u'  %s%s' % (align("[14]Setuid check"),printf(self.setuid_check())))
        print(u'  %s%s' % (align("[15]Startup check"),printf(self.startup_check())))
        print(u'  %s%s' % (align("[16]Alias check"),printf(self.alias_check())))
        print(u'  %s%s' % (align("[17]Openssh check"),printf(self.openssh_check())))
        print(u'  %s%s' % (align("[18]Fstab check"),printf(self.fstab_check())))
        print(u'  %s%s' % (align("[19]Setgid check"),printf(self.setgid_check())))
        print(u'  %s%s' % (align("[20]PAM check"),printf(self.pam_check())))
        for detail in self.suspicious_backdoor:
            print(u'    [*]File:%s[*]Detail:%s'%(align(detail[0]),detail[1]))
