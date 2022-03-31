import os,re,string
def printf(run):
    if run:
        return "\033[1;32m[ OK ]\033[0m"
    else:
        return "\033[1;31m[Warn]\033[0m"

def getfile(filepath):
    filename = []
    try:
        files = os.listdir(filepath)
        for fi in files:
            fi_d = os.path.join(filepath, fi)
            if os.path.isdir(fi_d):
                filename = filename + getfile(fi_d)
            else:
                filename.append(os.path.join(filepath, fi_d))
        return filename
    except:
        return filename

def strings(files):
    nonprintable = re.compile(b'[^%s]+' % re.escape(string.printable.encode('ascii')))
    with open(files,"rb") as f:
        for result in nonprintable.split(f.read()):
            if len(result)>4:
                yield result.decode('ASCII')

def align(string,width=30):
    if len(string)<width:
        return string+" "*(width-len(string))
    else:return string

# THIS GOT PROBLEM
# Singleton to get memory used properly
class allfile:
    _instance = None
    _status = False
    dir_list = []
    file_list = []

    def __new__(cls):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def getallfile(cls):
        for dirpath,dirs,files in os.walk("/"):
            for name in files:
                cls.file_list.append(os.path.join(dirpath,name))
            for name in dirs:
                cls.dir_list.append(os.path.join(dirpath, name))
        cls._status = True


