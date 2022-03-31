'''
@Author: chriskali
'''
import os,stat
from plugins.common.common import getfile,strings
class check_all:
    def __init__(self):
        pass

    @staticmethod
    def check_shell(content):
        '''check suspicious shell'''
        try:
            if 'docker' in content:
                return False
            if (('sh' in content) and (
                    ('/dev/tcp/' in content) or ('telnet ' in content) or ('nc ' in content) or (
                    ('exec ' in content) and ('socket' in content)) or ('curl ' in content) or (
                        'wget ' in content) or ('lynx ' in content))) or (".decode('base64')" in content):
                return content
            elif ('/dev/tcp/' in content) and (('exec ' in content) or ('ksh -c' in content)):
                return content
            elif ('sh -i' in content):
                return content
            elif ('exec ' in content) and (('socket.' in content) or (".decode('base64')" in content)):
                return content
            elif ('socket.socket' in content):
                return content
            #
            # Ruby added
            #
            elif (('wget ' in content) or ('curl ' in content)) and (
                    (' -O ' in content) or (' -s ' in content)) and (
                    ' http' in content) and (
                    ('php ' in content) or ('perl' in content) or 
                    ('ruby ' in content) or ('python ' in content) or 
                    ('sh ' in content) or ('bash ' in content)):
                return content
            return False
        except:
            return False

##SHOULD have better way
class analysis:
    def __init__(self):
        pass
    @staticmethod
    def history(contents):
        try:
            content = contents.replace('\n','')
            if check_all.check_shell(content):
                return True
            return False
        except:
            return False
    
    @staticmethod
    def checkfile(path):
        try:
            return_list = []
            if not stat.S_ISREG(os.stat(path).st_mode):
                return False
            result = strings(path)
            for i in result:
                try:
                    under_check = next(result)
                    if len(under_check) < 3:continue
                    if under_check[0] == "#":continue
                    content = check_all.check_shell(under_check)
                    if content:return_list.append([path,under_check])
                except:
                    pass
            return return_list
        except:
            return False
