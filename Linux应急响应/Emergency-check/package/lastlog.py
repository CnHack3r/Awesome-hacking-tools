import struct
import datetime


###NEED UID,SO RUN THEM ALL
def lastlog(path,uid):
    with open(path,"rb") as fd:
        fd.read(292)
        fd.seek(292*int(uid))
        match = fd.read(292)
        try:
            data = struct.unpack_from("I32s256s", match)
            if (data[0] == 0):
                return False
            return [datetime.datetime.utcfromtimestamp(data[0]).strftime("%Y-%m-%d %H:%M:%S"), (data[1].rstrip(b'\0')).decode('utf8'), (data[2].rstrip(b'\0')).decode('utf8')]
        except:
            return False