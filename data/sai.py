import time
import json

from psotify import spotify_album_info
sai = spotify_album_info('jsyqrt', 'jsyqrt_xhwj')

ALBUM_TRACK_PLAYCOUNT_SQL_FILE = '/home/liuqian/test/p/spotify/psotify/atpsf.sql'
ALBUM_INFO_TXT_FILE = '/home/liuqian/test/p/spotify/psotify/aitf.txt'

def deal_album_info_insert_into_sql_file(header, body):
    with open(ALBUM_TRACK_PLAYCOUNT_SQL_FILE, 'a') as f:
        try:
            track_infos = json.loads(body[0].decode('utf8')).get('discs')[0].get('tracks')
            track_id_playcount_map = list(map(lambda x: '(%s, %d)' % (x.get('uri').split(':')[2], x.get('playcount')), track_infos))
            sql = 'insert into spotify_track_playcount values %s;\n' % (','.join(track_id_playcount_map))
            f.write(sql)
            print('finished with %s' %id)
        except:
            print('error with %s' %id)
            
def deal_album_info_write_to_file(header, body):
    with open(ALBUM_INFO_TXT_FILE, 'a') as f:
        try:
            f.write('uri:%s\tstatus_code:%d\tbody:%s\n' % (header.uri, header.status_code, body[0].decode('utf8')))
            print('finished with %s' %id)
        except:
            f.write('error\n')
            print('error with %s' %id)

with open('sra.json', 'r') as f:
    for line in f:
        id = json.loads(line.rstrip('\n')).get('id')
        try:
            sai.get_album_info_by_id(id, deal_album_info_write_to_file)
        except:
            pass
        time.sleep(1)


