# coding: utf-8
# psotify.py
# go to end of the file to see the usage :)

import os, sys, subprocess, socket, struct, inspect, random, hmac, hashlib, enum, threading, time
import diffiehellman.diffiehellman as diffiehellman
import shannon, pyaes

# patch DH with non RFC prime to be used for handshake
if not 1 in diffiehellman.PRIMES:
    diffiehellman.PRIMES.update( { 1: { 
        "prime": 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff,
        "generator": 2
    } } )

try:
    import protocol.impl.keyexchange_pb2 as keyexchange
    import protocol.impl.authentication_pb2 as authentication
    import protocol.impl.mercury_pb2 as mercury
    import protocol.impl.metadata_pb2 as metadata
except:
    raise Exception( "PROTO stubs were not found or have been corrupted. Please regenerate from .proto files using process_proto.py" ) 

KEY_LENGTH=                 96
SPOTIFY_AP_ADDRESS=         ( 'guc3-accesspoint-b-cz1w.ap.spotify.com', 80 )
SPOTIFY_API_VERSION=        0x10800000000
INFORMATION_STRING=         "pyspotify2"
DEVICE_ID=                  "452198fd329622876e14907634264e6f332e9fb3"
VERSION_STRING=             "pyspotify2-0.1"

LOGIN_REQUEST_COMMAND=          0xAB
AUTH_SUCCESSFUL_COMMAND=        0xAC
AUTH_DECLINED_COMMAND=          0xAD

FIRST_REQUEST=                  0x04
AUDIO_CHUNK_REQUEST_COMMAND=    0x08
AUDIO_CHUNK_SUCCESS_RESPONSE= 0x09
AUDIO_CHUNK_FAILURE_RESPONSE= 0x0A
AUDIO_KEY_REQUEST_COMMAND=      0x0C
AUDIO_KEY_SUCCESS_RESPONSE=     0x0D
AUDIO_KEY_FAILURE_RESPONSE=     0x0E
COUNTRY_CODE_RESPONSE=          0x1B

MAC_SIZE=                       4
HEADER_SIZE=                    3
MAX_READ_COUNT=                 5
INVALID_COMMAND=                0xFFFF
AUDIO_CHUNK_SIZE=               0x20000

AUDIO_AESIV=                    b'\x72\xe0\x67\xfb\xdd\xcb\xcf\x77\xeb\xe8\xbc\x64\x3f\x63\x0d\x93'
BASE62_DIGITS=                  b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
ALBUM_INFO_PATH_TEMPLATE=       'hm://album/v1/album-app/album/spotify:album:%s/desktop?catalogue=premium&locale=it&username=%s'
ARTIST_INFO_PATH_TEMPLATE=      'hm://artist/v1/%s/desktop?format=json&catalogue=free&locale=it&username=%s'

"""
    Convert from 62 symbol alphabet -> 16 symbols
"""
def _toBase16( id62 ):
    result= 0x00000000000000000000000000000000
    for c in id62:
        result= result* 62+ BASE62_DIGITS.find( bytes( [c] ) )
      
    return result


class REQUEST_TYPE(enum.Enum):
    SEND=      1
    GET =      2
    
    def __str__(self):
        return self.name
      
    def as_command( self ):
        if self.name== 'SEND' or self.name== 'GET':
            return 0xb2


class Connection:
    class CONNECT_TYPE(enum.Enum):
        CONNECT_TYPE_HANDSHAKE= 1
        CONNECT_TYPE_STREAM=    2

    def __init__( self ):
        self._socket = socket.socket(socket.AF_INET, 
                                  socket.SOCK_STREAM)
        self._socket.connect( SPOTIFY_AP_ADDRESS )
        self._connect_type= Connection.CONNECT_TYPE.CONNECT_TYPE_HANDSHAKE
        self._partial_buffer= b''

    def _try_recv( self, size ):
        result= self._partial_buffer
        read_count= 0
        while read_count< MAX_READ_COUNT and len( result )< size:
            try:
                result+= self._socket.recv( size- len( result ) )
            except socket.timeout:
                read_count+= 1
        
        if len( result )< size:
            self._partial_buffer= result
        else:
            self._partial_buffer= b''
      
        return result

    def send_packet( self, 
                     prefix, 
                     data ):
        if prefix== None:
            prefix= b""
      
        if self._connect_type== Connection.CONNECT_TYPE.CONNECT_TYPE_HANDSHAKE:
            size=    len( prefix )+ 4+ len( data )
            request= prefix+ struct.pack(">I", size )+ data
        else:
            self._encoder.set_nonce( self._encoder_nonce )
            self._encoder_nonce+= 1

            request= bytes( [ prefix ] )+ struct.pack(">H", len( data ) )+ data
            request= self._encoder.encrypt( request )
            request+= self._encoder.finish( MAC_SIZE )

        self._socket.send( request )
        return request

    def recv_packet( self, timeout= 0 ):
        if timeout:
            self._socket.setblocking( 0 )
            self._socket.settimeout( timeout )
        else:
            self._socket.setblocking( 1 )
          
        if self._connect_type== Connection.CONNECT_TYPE.CONNECT_TYPE_HANDSHAKE:
            size_packet= self._socket.recv( 4 )
            size= struct.unpack( ">I",  size_packet )
            return '', size[ 0 ], size_packet+ self._socket.recv( size[ 0 ]- 4 )
        else:
            command= INVALID_COMMAND
            size= 0
            body= b''
            recv_header= self._try_recv( HEADER_SIZE )
            
            if len( recv_header )== HEADER_SIZE:
                if not self._partial_buffer:
                    self._decoder.set_nonce( self._decoder_nonce )
                    self._decoder_nonce+= 1
      
                header= self._decoder.decrypt( recv_header )
                size= struct.unpack( ">H", header[ 1: ] )[ 0 ]
                command= header[ 0 ]
                recv_body= self._try_recv( size )
                if len( recv_body )== size:
                    mac= self._try_recv( MAC_SIZE )
                    if len( mac )== MAC_SIZE:
                    
                        body= self._decoder.decrypt( recv_body )
                        calculated_mac= self._decoder.finish( MAC_SIZE )
                        if calculated_mac!= mac:
                            raise Exception( 'RECV MAC not matching', calculated_mac, mac )
                    else:
                        self._partial_buffer= recv_header+ recv_body+ self._partial_buffer
                else:
                  self._partial_buffer= recv_header+ self._partial_buffer
                  print( 'Size is not matching expected length %d vs %d' % ( size, len( recv_body )) )
            
            return command, size, body
  
    def handshake_completed( self, send_key, recv_key ):
        self._connect_type= Connection.CONNECT_TYPE.CONNECT_TYPE_STREAM
        
        # Generate shannon streams
        self._encoder_nonce= 0
        self._encoder= shannon.Shannon( send_key )
        
        self._decoder_nonce= 0
        self._decoder= shannon.Shannon( recv_key )
        

class Session:
    def _sendClientHelloRequest(self):
        diffiehellman_hello= keyexchange.LoginCryptoDiffieHellmanHello( 
                **{'gc': self._local_keys.public_key.to_bytes(KEY_LENGTH, byteorder='big'), \
                'server_keys_known': 1})                                            
  
        request = keyexchange.ClientHello(
                **{'build_info': keyexchange.BuildInfo(
                    **{'product': keyexchange.PRODUCT_PARTNER, 
                        'platform': keyexchange.PLATFORM_LINUX_X86, 
                        'version':  SPOTIFY_API_VERSION
                        }
                    ),
                    'cryptosuites_supported': [keyexchange.CRYPTO_SUITE_SHANNON],
                    'login_crypto_hello': keyexchange.LoginCryptoHelloUnion(
                        **{'diffie_hellman': diffiehellman_hello}
                        ),
                    'client_nonce': bytes([int(random.random()* 0xFF) for x in range(0, 0x10)]),
                    'padding': bytes([0x1E]),
                    'feature_set': keyexchange.FeatureSet(**{'autoupdate2': True})
                    }
                )
        return self._connection.send_packet(b"\x00\x04", request.SerializeToString())
      
    def _processAPHelloResponse(self, init_client_packet):
        prefix, size, init_server_packet= self._connection.recv_packet()
        response= keyexchange.APResponseMessage()
        response.ParseFromString(init_server_packet[4:])
        remote_key= response.challenge.login_crypto_challenge.diffie_hellman.gs
        self._local_keys.generate_shared_secret(int.from_bytes(remote_key, byteorder='big'));
        mac_original= hmac.new(
                self._local_keys.shared_secret.to_bytes(KEY_LENGTH, byteorder='big' ), 
                digestmod= hashlib.sha1)
        data= []
        for i in range(1, 6):
            mac= mac_original.copy()
            mac.update(init_client_packet + init_server_packet + bytes([i]))
            data+= mac.digest()
          
        mac= hmac.new(bytes(data[:0x14]), 
                       digestmod= hashlib.sha1)
        mac.update(init_client_packet+ init_server_packet)
        
        return (mac.digest(), bytes(data[0x14: 0x34]), bytes(data[0x34: 0x54]))
  
    def _sendClientHandshakeChallenge(self, challenge):
        diffie_hellman= keyexchange.LoginCryptoDiffieHellmanResponse(**{'hmac': challenge})
        crypto_response= keyexchange.LoginCryptoResponseUnion(**{'diffie_hellman': diffie_hellman})
        packet = keyexchange.ClientResponsePlaintext(
                **{'login_crypto_response': crypto_response,
                    'pow_response': {},
                    'crypto_response': {}
                    }
                )
        self._connection.send_packet(prefix= None, data= packet.SerializeToString())
                 
    def connect(self, connection):
        self._connection= connection 
        init_client_packet= self._sendClientHelloRequest()
        challenge, send_key, recv_key= self._processAPHelloResponse(init_client_packet)
        self._sendClientHandshakeChallenge(challenge)
        self._connection.handshake_completed(send_key, recv_key)
        return self                                   
      
    def authenticate(self, username, auth_data, auth_type):
        auth_request = authentication.ClientResponseEncrypted(
                **{'login_credentials': authentication.LoginCredentials(
                    **{'username': username,
                        'typ': auth_type, 
                        'auth_data': auth_data
                        }
                    ),
                    'system_info': authentication.SystemInfo(
                        **{'cpu_family': authentication.CPU_UNKNOWN, 
                            'os': authentication.OS_UNKNOWN, 
                            'system_information_string': INFORMATION_STRING, 
                            'device_id': DEVICE_ID
                            }
                        ),
                    'version_string': VERSION_STRING
                    }
                )
        packet= self._connection.send_packet(
                LOGIN_REQUEST_COMMAND, auth_request.SerializeToString())
        # Get response
        command, size, body= self._connection.recv_packet()
        if command== AUTH_SUCCESSFUL_COMMAND:
            auth_welcome= authentication.APWelcome()
            auth_welcome.ParseFromString(body)
            return auth_welcome.reusable_auth_credentials
        elif command== AUTH_DECLINED_COMMAND:
            raise Exception('AUTH DECLINED. Code: %02X' % command)
        
        raise Exception('UNKNOWN AUTH CODE %02X' % command)
        
    def __init__(self):
        # Generate local keys`
        self._local_keys= diffiehellman.DiffieHellman(group=1, key_length=KEY_LENGTH)
        self._local_keys.generate_private_key()
        self._local_keys.generate_public_key()


class MercuryManager(threading.Thread):
    
    def __init__(self, connection):
        super(MercuryManager, self).__init__()
        self._connection= connection
        self._sequence= 0x0000000000000000
        self._audio_key_sequence=   int(0)
        self._audio_chunk_sequence= 0
        self._callbacks= {}
        self._terminated= False
        self.start()
        self._country= None
        self._audio_chunk_callback= None
        
    def get_country(self):
        return self._country

    def set_callback(self, seq_id, func):
        self._callbacks[seq_id]= func
    
    def is_terminated(self):
        return self._terminated
      
    def terminate(self):
        self._terminated= True
      
    def _process04(self, data):
        self._connection.send_packet(0x49, data)

    def _process_country_response(self, data):
        self._country= data.decode("ascii")

    def _process_audio_key(self, data):
        if len(data)>= 20:
            seq_id= int.from_bytes(data[:4], byteorder='big')
            try:
                callback= self._callbacks[seq_id]
                del(self._callbacks[seq_id])
            except:
                callback= None
            
            if callback:
                callback(data[4:])
            else:
                print('Callback for key %d is not found' % seq_id)
        else:
            print('Wrong format of the key response', data)
      
    def _process_audio_key_failure(self, data):
        print('Key cannot be retrieved', data)
       
    def _parse_response(self, payload):
        return int.from_bytes(payload[2: 10], byteorder='big'), payload
      
    def run(self):
        while not self._terminated:
            try:
                response_code, size, payload= self._connection.recv_packet(0.5)

                if response_code== FIRST_REQUEST:
                    self._process04(payload)
                elif response_code== COUNTRY_CODE_RESPONSE:
                    self._process_country_response(payload)
                elif response_code== AUDIO_KEY_SUCCESS_RESPONSE:
                    self._process_audio_key(payload)
                elif response_code== AUDIO_KEY_FAILURE_RESPONSE:
                    self._process_audio_key_failure(payload)
                elif response_code== AUDIO_CHUNK_SUCCESS_RESPONSE or \
                    response_code== AUDIO_CHUNK_FAILURE_RESPONSE:
                    self._audio_chunk_callback and self._audio_chunk_callback(success=(response_code== AUDIO_CHUNK_SUCCESS_RESPONSE), payload= payload)
                elif response_code== REQUEST_TYPE.GET.as_command():
                    seq_id, body= self._parse_response(payload)
                    try:
                        callback, metadata= self._callbacks[seq_id]
                    except:
                        callback= None
                    
                    if callback:
                        callback(body, metadata)
                        if callback.__dict__['finished']:
                            del(self._callbacks[seq_id])
                    else:
                        print('Callback for', seq_id, 'is not found') 
                    
                elif response_code!= INVALID_COMMAND:
                    print( 'Received unknown response:', hex( response_code ), ' len ', size )
                    pass
                  
                """
                    0x4a => (), 
                    0x9 | 0xa => self.channel().dispatch(cmd, data),
                    0xd | 0xe => self.audio_key().dispatch(cmd, data),
                    0xb2...0xb6 => self.mercury().dispatch(cmd, data),
                """
            except socket.timeout:
                pass

    def execute(self, request_type, uri, callback, metadata):
        header= mercury.Header(
                **{'uri': uri,
                    'method': str(request_type),
                    }
                )
        buffer= b'\x00\x08'+   \
                self._sequence.to_bytes(8, byteorder='big')+  \
                b'\x01'+       \
                b'\x00\x01'+   \
                struct.pack(">H", len(header.SerializeToString()))+ \
                header.SerializeToString()
        self.set_callback(self._sequence, (callback, metadata))
        self._sequence+= 1
        self._connection.send_packet(request_type.as_command(), buffer)   
      
    def request_audio_key(self, track_id, file_id, callback):
        buffer= file_id.to_bytes(20, byteorder='big')+                 \
                track_id.to_bytes(16, byteorder='big')+                \
                self._audio_key_sequence.to_bytes(4, byteorder='big')+ \
                b'\x00\x00'
        self.set_callback(self._audio_key_sequence, callback)
        self._audio_key_sequence+= 1
        self._connection.send_packet(AUDIO_KEY_REQUEST_COMMAND, buffer)   

class psotify:
    def __init__(self, username, password):
        '''
        spotify premium account needed!
        '''
        self.username = username
        self.password = password
        self.connection = Connection()
        self.session = Session().connect(self.connection)
        self.token = self.session.authenticate(
            self.username,
            bytes(self.password, 'ascii'),
            authentication.AUTHENTICATION_USER_PASS
            )
        self.manager = MercuryManager(self.connection)
        self.metadata = {'artist_info': {}, 'artist_id': ''}
    
    def get_artist_by_id(self, artist_id, artist_info_callback, metadata):
        metadata = {'metadata': metadata, 'artist_id': artist_id}
        self.manager.execute(
            REQUEST_TYPE.GET, 
            ARTIST_INFO_PATH_TEMPLATE % (artist_id, self.username),
            self.artist_info_callback, 
            (artist_info_callback, metadata),
            )
        pass

    def get_album_by_id(self, album_id, album_info_callback, metadata):
        self.manager.execute(
            REQUEST_TYPE.GET, 
            ALBUM_INFO_PATH_TEMPLATE % (album_id, self.username),
            self.album_info_callback, 
            (album_info_callback, metadata),
            )
        pass

    def reconnect(self):
        self.manager.terminate()
        self.manager = MercuryManager(self.connection)
    
    def quit(self):
        self.manager.terminate()

    def album_info_callback(self, body, metadata):
        user_callback, metadata = metadata
        body = body.decode('utf8', errors='ignore')
        body = body[body.find('{"uri": "spotify:album:'):]
        user_callback(body, metadata)
        self.album_info_callback.__dict__['finished'] = True
    
    def artist_info_callback(self, body, metadata):
        user_callback, metadata = metadata
        self.metadata['artist_id'] = metadata['artist_id']
        body = body.decode('utf8', errors='ignore')
        if body.find('hm://artist/') in range(15, 20):
            body = body[body.find('{"uri": "spotify:artist:'):]
            self.metadata['artist_info'][self.metadata['artist_id']] = body
        else:
            if ord(body[14]) > 32:
                body = body[14:]
            else:
                body = body[15:]
            self.metadata['artist_info'][self.metadata['artist_id']] += body
        if body.endswith('}}'):
            result = self.metadata['artist_info'][self.metadata['artist_id']]
            user_callback(result, metadata['metadata'])
            self.artist_info_callback.__dict__['finished']=True
        else:
            self.artist_info_callback.__dict__['finished']=False

if __name__ == '__main__':
    # example usage
    sai = psotify('jsyqrt', 'jsyqrt_xhwj') # username, password of spotify premium account.
    album_ids = ['5MfAxS5zz8MlfROjGQVXhy', '02H4kc9YLgorpUIREOwa0q']
    artist_ids = ['1vPoTjMgGQuiCzsgvpASWW', '3yfDRplDZh03Y0fEeCd6B0']
    callback = lambda x, y: print(x, y)
    metadata = 'hello spotify'
    for id in album_ids:
        sai.get_album_by_id(id, callback, metadata)
    for id in artist_ids:
        sai.get_artist_by_id(id, callback, metadata)
