import json
from psotify import psotify

a = psotify('jsyqrt', 'jsyqrt_xhwj')

def single_callback(body, metadata):
    body = body.decode('utf8', errors='ignore')
    body = json.loads(body[body.find('{"uri": "spotify:album:'):])
    single_callback.finished = True
    
    try:
        for single in body.get('discs')[0].get('tracks'):
            result = metadata + (body.get('name'), body.get('uri'), single.get('name'), single.get('uri'), single.get('popularity'), single.get('playcount'))
            print(result)
    except:
        print(False, 'singles', body.get('discs'))

def output_result(json_artist_result):
    j = json_artist_result
    albums = j.get('releases').get('albums').get('releases', [])
    singles = j.get('releases').get('singles').get('releases', [])
    name = j.get('info').get('name')
    uri = j.get('uri')

    for album in albums:
        
        try:
            for track in album.get('discs')[0].get('tracks'):
                result = (name, uri, album.get('name'), album.get('uri'), track.get('name'), track.get('uri'), track.get('popularity'), track.get('playcount'))
                print(result)
        except:
            singles.append(album)

    for single in singles:
        single_uri = single.get('uri').split(':')[-1]
        a.get_album_by_id(single_uri, single_callback, (name, uri))
            
        
def lbl(ff):
    with open(ff, 'r') as f:
        for line in f:
            output_result(json.loads(line))

ff='asked_artists.json'
lbl(ff)
