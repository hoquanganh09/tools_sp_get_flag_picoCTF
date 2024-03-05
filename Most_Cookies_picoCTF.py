import hashlib
from itsdangerous import URLSafeTimedSerializer
from itsdangerous.exc import BadTimeSignature
from flask.sessions import TaggedJSONSerializer

def flask_cookie(secret_keys, cookie_str, encode_str=None):
    salt = 'cookie-session'
    serializer = TaggedJSONSerializer()
    signer_kwargs = {
        'key_derivation': 'hmac',
        'digest_method': hashlib.sha1
    }
    for secret_key in secret_keys:
        s = URLSafeTimedSerializer(secret_key, salt=salt, serializer=serializer, signer_kwargs=signer_kwargs)
        try:
            decoded_cookie = s.loads(cookie_str)
            if encode_str:
                encoded_str = s.dumps(encode_str)
                return decoded_cookie, secret_key, encoded_str
            else:
                return decoded_cookie, secret_key
        except BadTimeSignature:
            continue
    return None, None

# Input secret keys
secret_keys = [
    "snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", 
    "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", 
    "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", 
    "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", 
    "white chocolate macadamia"
]

# Input cookie string
cookie_str = input("Enter cookie string: ")

# Input string to encode
encode_str = input("Enter string to encode (leave empty if not encoding): ")

decoded_cookie, secret_key, encoded_str = flask_cookie(secret_keys, cookie_str, encode_str)
if decoded_cookie is not None:
    print("Decoded cookie:", decoded_cookie)
    print("Used secret key:", secret_key)
    if encode_str:
        print("Encoded string:", encoded_str)
else:
    print("Failed to decode cookie.")

