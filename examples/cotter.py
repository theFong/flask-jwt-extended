# https://www.cotter.app/
# An example of how to use Cotter's access keys

import functools
import requests
import jwcrypto.jwk
import json

import flask
import flask_jwt_extended


app = flask.Flask(__name__)


@functools.lru_cache(1)
def get_cotter_public_key():
    resp = requests.get("https://www.cotter.app/api/v0/token/jwks")
    data = resp.json()
    key = data["keys"][0]
    return key


def jwk_to_pem(jwk):
    public_key_json = json.dumps(jwk)
    pk = jwcrypto.jwk.JWK.from_json(public_key_json)
    pem = pk.export_to_pem()
    return pem


app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["JWT_ALGORITHM"] = "ES256"
app.config[
    "JWT_DECODE_AUDIENCE"
] = "ec9edfa5-94a8-4344-a7cd-fbe7a54b1bd5"  # Cotter API key
app.config["JWT_PRIVATE_KEY"] = ""
app.config["JWT_PUBLIC_KEY"] = jwk_to_pem(get_cotter_public_key())
app.config["JWT_IDENTITY_CLAIM"] = "sub"  # field for cotter user id


jwt = flask_jwt_extended.JWTManager(app)


@jwt.token_loader
def load_token(token):
    if "type" in token and token["type"] == "client_access_token":
        token["type"] = "access"
    return token


@app.route("/protected", methods=["GET"])
@flask_jwt_extended.jwt_required
def protected():
    cotter_user_id = flask_jwt_extended.get_jwt_identity()

    # logic here

    return flask.jsonify(secret_message="go banana!")


if __name__ == "__main__":
    app.run()

