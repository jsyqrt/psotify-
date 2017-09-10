import time
import json

from psotify import spotify_album_info

def deal_album_info(header, body):
    with open('/home/liuqian/test/p/spotify/psotify/data.txt', 'a') as f:
        try:
            f.write('uri:%s\tstatus_code:%d\tbody:%s\n' % (header.uri, header.status_code, body[0].decode('utf8')))
            print('finished with %s' %id)
        except:
            f.write('error\n')
            print('error with %s' %id)

with open('asked.json', 'r') as f:
    n = 0
    sai = spotify_album_info('jsyqrt', 'jsyqrt_xhwj')
    for line in f:
        id = json.loads(line.rstrip('\n')).get('id')
        try:
            n = (n+1) % 300
            if n == 0:
                sai.reconnect()
            sai.get_album_info_by_id(id, deal_album_info)
        except:
            pass
        time.sleep(0.1)
