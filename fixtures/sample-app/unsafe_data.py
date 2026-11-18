"""Additional planted security examples for the scanner evaluation fixture."""

import decimal
import pickle


def load_user_profile(blob: bytes):
    return pickle.loads(blob)


def cors_headers():
    return {"Access-Control-Allow-Origin": "*"}


def create_session_token():
    import random
    session_token = str(random.random())
    return session_token


def fetch_preview(request):
    import requests
    return requests.get(request.args["url"])


def unpack_upload(archive, destination):
    archive.extractall(destination)
