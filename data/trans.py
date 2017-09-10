import json

def deal_album_info_insert_into_sql_file(line, tf):
    with open(tf, 'a') as f:
        try:
            body = line.split('\t')[2].lstrip('body:')
            track_infos = json.loads(body.get('discs')[0].get('tracks'))
            track_id_playcount_map = list(map(lambda x: '(%s, %d)' % (x.get('uri').split(':')[2], x.get('playcount')), track_infos))
            sql = 'insert into spotify_track_playcount values %s;\n' % (','.join(track_id_playcount_map))
            f.write(sql)
        except:
            print('error with %s' %line.split('\t')

def line_by_line(ff, tf):
    with oepn(ff, 'r') as f:
        for line in f:
            deal_album_info_insert_into_file(line, tf)
            
ff='x.txt'
tf='x.sql'
line_by_line(ff, tf)
