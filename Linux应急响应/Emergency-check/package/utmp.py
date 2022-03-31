import collections
from enum import Enum
import struct
import datetime
class UTmpRecordType(Enum):
    empty = 0
    run_lvl = 1
    boot_time = 2
    new_time = 3
    old_time = 4
    init_process = 5
    login_process = 6
    user_process = 7
    dead_process = 8
    accounting = 9

class UTmpRecord(collections.namedtuple('UTmpRecord',
                                        'type pid line id user host exit0 exit1 session' +
                                        ' sec usec addr0 addr1 addr2 addr3 unused')):

    @property
    def type(self):
        return UTmpRecordType(self[0])

    @property
    def time(self):
        return datetime.datetime.fromtimestamp(self.sec) + datetime.timedelta(microseconds=self.usec)

STRUCT = struct.Struct('hi32s4s32s256shhiii4i20s')

def readlog(buf):
    def convert_string(val):
        if isinstance(val, bytes):
            return val.rstrip(b'\0').decode()
        return val

    offset = 0
    while offset < len(buf):
        yield UTmpRecord._make(map(convert_string, STRUCT.unpack_from(buf, offset)))
        offset += STRUCT.size