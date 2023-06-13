from datetime import datetime, timedelta
import traceback
import base64
import os

from flask import Flask, request, Response, jsonify
from flask_cors import CORS
import requests
from jose import jwt as joseJwt

JWK = None
JWK_EXPIRY = None

try:
    CLIENT_ID = os.environ['CLIENT_ID']
except KeyError:
    raise Exception('CLIENT_ID environment variable not set')
try:
    CLIENT_SECRET = os.environ['CLIENT_SECRET']
except KeyError:
    raise Exception('CLIENT_SECRET environment variable not set')

AUTHORIZATION = f'{CLIENT_ID}:{CLIENT_SECRET}'
AUTHORIZATION = AUTHORIZATION.encode('utf-8')
AUTHORIZATION = base64.b64encode(AUTHORIZATION)
AUTHORIZATION = AUTHORIZATION.decode('utf-8')
AUTHORIZATION = f'Basic {AUTHORIZATION}'

app = Flask(__name__)
CORS(app)

def esi_request(code):
    return requests.post(
        url='https://login.eveonline.com/v2/oauth/token',
        data={
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
    return joseJwt.decode(
        jwt,
        JWK,
        algorithms=[JWK['alg']],
        audience="EVE Online",
        issuer="login.eveonline.com",
    )

@app.route('/', methods=['POST'])
def login():
    global JWK, JWK_EXPIRY

    code = request.args.get('code')
    if code is None:
        return jsonify({ 'err': 'Request missing ESI Authorization Code' }), 400
    
    esi_rep = esi_request(code)
    if esi_rep.status_code != 200:
        return jsonify({ 'err': 'Problem authenticating with ESI' }), esi_rep.status_code
    
    try:
        esi_json = esi_rep.json()
    except:
        print(traceback.format_exc())
        return jsonify({ 'err': 'ESI Response was not JSON' }), 500
    
    refresh_token = esi_json.get('refresh_token')
    if refresh_token is None:
        return jsonify({ 'err': 'ESI Response missing Refresh Token' }), 500
    
    jwt = esi_json.get('access_token')
    if jwt is None:
        return jsonify({ 'err': 'ESI Response missing Access Token' }), 500
    
    if JWK is None or JWK_EXPIRY is None or JWK_EXPIRY < datetime.now():
        jwks_rep = jwks_request()
        if jwks_rep.status_code != 200:
            return jsonify({ 'err': 'Problem getting JWKS' }), jwks_rep.status_code,
        
        try:
            jwks_json = jwks_rep.json()
        except:
            print(traceback.format_exc())
            return jsonify({ 'err': 'JWKS Response was not JSON' }), 500
        
        jwks = jwks_json.get('keys')
        if jwks is None or len(jwks) == 0:
            return jsonify({ 'err': 'JWKS Response missing Keys' }), 500
        
        JWK = jwks[0]

        # Set JWK_EXPIRY to be 24 hours from now
        JWK_EXPIRY = datetime.now() + timedelta(hours=24)

    try:
        decoded_jwt = decode_jwt(jwt)
    except:
        print(traceback.format_exc())
        return jsonify({ 'err': 'JWT could not be decoded' }), 500
    
    character_id = decoded_jwt.get('sub')
    if character_id is None or len(character_id) < 15:
        return jsonify({ 'err': 'JWT missing Character ID' }), 500
    
    try:
        character_id = int(character_id[14:])
    except:
        print(traceback.format_exc())
        return jsonify({ 'err': 'JWT Character ID was Invalid' }), 500
    
    character_name = decoded_jwt.get('name')
    if character_name is None:
        return jsonify({ 'err': 'JWT missing Character Name' }), 500
    
    return jsonify({
        'characterId': character_id,
        'characterName': character_name,
        'refreshToken': refresh_token,
    }), 200
