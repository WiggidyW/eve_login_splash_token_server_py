from datetime import datetime, timedelta
import base64
import os

from flask import Flask, request, Response
import requests
import jose

try:
    CLIENT_ID = os.environ['CLIENT_ID']
except KeyError:
    raise Exception('CLIENT_ID environment variable not set')
try:
    CLIENT_SECRET = os.environ['CLIENT_SECRET']
except KeyError:
    raise Exception('CLIENT_SECRET environment variable not set')
AUTHORIZATION = 'Basic ' + base64.b64encode(
    f"{CLIENT_ID}:{CLIENT_SECRET}".encode("utf-8")
)\
    .decode("utf-8")
JWK = None
JWK_EXPIRY = None

def esi_request(code):
    return requests.post(
        'https://login.eveonline.com/v2/oauth/token',
        params={
            'grant_type': 'authorization_code',
            'code': code,
        },
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': AUTHORIZATION,
            'Host': 'login.eveonline.com',
        },
    )

def jwks_request():
    return requests.get('https://login.eveonline.com/oauth/jwks')

def decode_jwt(jwt):
    return jose.jwt.decode(
        jwt=jwt,
        key=JWK,
        algorithms=[JWK['alg']],
        audience="EVE Online",
        issuer="login.eveonline.com",
    )

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    code = request.args.get('code')
    if code is None:
        return Response(
            response='Request missing ESI Authorization Code',
            status=400
        )
    
    esi_rep = esi_request(code)
    if esi_rep.status_code != 200:
        return Response(
            response='Problem authenticating with ESI',
            status=esi_rep.status_code,
        )
    
    try:
        esi_json = esi_rep.json()
    except:
        return Response(
            response='ESI Response was not JSON',
            status=500,
        )
    
    refresh_token = esi_json.get('refresh_token')
    if refresh_token is None:
        return Response(
            response='ESI Response missing Refresh Token',
            status=500,
        )
    
    jwt = esi_json.get('access_token')
    if jwt is None:
        return Response(
            response='ESI Response missing Access Token',
            status=500,
        )
    
    if JWK is None or JWK_EXPIRY is None or JWK_EXPIRY < datetime.now():
        jwks_rep = jwks_request()
        if jwks_rep.status_code != 200:
            return Response(
                response='Problem getting JWKS',
                status=jwks_rep.status_code,
            )
        
        try:
            jwks_json = jwks_rep.json()
        except:
            return Response(
                response='JWKS Response was not JSON',
                status=500,
            )
        
        jwks = jwks_json.get('keys')
        if jwks is None or len(jwks) == 0:
            return Response(
                response='JWKS Response missing Keys',
                status=500,
            )
        
        JWK = jwks[0]

        # Set JWK_EXPIRY to be 24 hours from now
        JWK_EXPIRY = datetime.now() + timedelta(hours=24)

    try:
        decoded_jwt = decode_jwt(jwt)
    except:
        return Response(
            response='JWT could not be decoded',
            status=500,
        )
    
    character_id = decoded_jwt.get('sub')
    if character_id is None or len(character_id) < 15:
        return Response(
            response='JWT missing Character ID',
            status=500,
        )
    
    try:
        character_id = int(character_id[14:])
    except:
        return Response(
            response='JWT Character ID was Invalid',
            status=500,
        )
    
    character_name = decoded_jwt.get('name')
    if character_name is None:
        return Response(
            response='JWT missing Character Name',
            status=500,
        )
    
    return Response(
        response={
            'character_id': character_id,
            'character_name': character_name,
            'refresh_token': refresh_token,
        },
        status=200,
    )
