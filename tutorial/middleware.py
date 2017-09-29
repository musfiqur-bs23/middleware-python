import re

from django.conf import settings
from django.urls import reverse
from django.shortcuts import redirect
from django.contrib.auth import logout
from django.http import JsonResponse
from jose import jwt

EXEMPT_URLS = [re.compile(settings.LOGIN_URL.lstrip('/'))]
if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
    EXEMPT_URLS += [re.compile(url) for url in settings.LOGIN_EXEMPT_URLS]

class LoginRequiredMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        assert hasattr(request, 'user')
        path = request.path_info.lstrip('/')
        print(path)
        url_is_exempt = any(url.match(path) for url in EXEMPT_URLS)

        if path == reverse('accounts:logout').lstrip('/'):
            logout(request)

        if request.user.is_authenticated() and url_is_exempt:
            return redirect(settings.LOGIN_REDIRECT_URL)
        elif request.user.is_authenticated() or url_is_exempt:
            return None
        else:
            return redirect(settings.LOGIN_URL)




AUTH0_DOMAIN = "musfiqur-bs23.auth0.com"
API_AUDIENCE = 'localhost:8000'
ALGORITHMS = ["RS256"]

# Cache the key available at https://{AUTH0_DOMAIN}/.well-known/jwks.json as a python dict
AUTH0_PUBLIC_KEY = {
    "keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "x5c": [
                "MIIDCTCCAfGgAwIBAgIJBOtSo1BCR/SiMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMTF211c2ZpcXVyLWJzMjMuYXV0aDAuY29tMB4XDTE3MDkyOTA2NTIyNloXDTMxMDYwODA2NTIyNlowIjEgMB4GA1UEAxMXbXVzZmlxdXItYnMyMy5hdXRoMC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDfZdpfnRr3ct8BD+lma8sd3aOxCTTeRCv8wjEg96N4lJLF5cCCGJwfQ//sGAxJsfpKCUk/+kpphtM39fd3Fk45YRPSzWLZeCkhbN2AX4GwM8eA+7wOrJKsERhOCmRIacGDhKnafBXa47J2/ofagfON835jeawj4SS2KeO2Vx+cyCaSqc6W2qw7AnG5fBDya6QDKN0FwFBeidfW2LptlRxIG5ZnbtA6Dnaj/2AF9Z2muKVNxjBfUt9a5SpO4cyeCjquJJgv9GRoO7lsJoJNMTdeS7RpQ0tg03g5X1OG2YIsaiAjHVHYXEy7cVukQM4qgCDnXDUSaaKdd6AibRv2zK0FAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFFDJ3Y9KdVRqQ9ynD2kDoPTRptIwMA4GA1UdDwEB/wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEAPz5Olx6kF5CdX0fyiQghgMb0y/E0yX40cqrvdthX2cW7AK3lAN0e7Ee3gaH1nJBWAc5XrDio2eYc4CzbjVfWH4b4Gx7lPhGiYw50/JU8r+VNVCLrprjmHkpy9xMgihZQzvGKmjSn3y//X2bcv0/BMQmsiDwecprhWccLiHrnc3keBxbFP5WvXGFUBTOnozTvq1+zxvjv2dAYccRwEIUlWdPNxtE36sUZBKSXGb3It2Jj5Fwfo/Hf9V0rWFLAX/Ffs15BqGmMhWP6cZ9D9lGuZodvm5F+j4eA5JQzHvsJzD00tATduH/ZJhe6QSWu3HmR11pPHQW/GwTYYX2GYsa3rA=="
            ],
            "n": "32XaX50a93LfAQ_pZmvLHd2jsQk03kQr_MIxIPejeJSSxeXAghicH0P_7BgMSbH6SglJP_pKaYbTN_X3dxZOOWET0s1i2XgpIWzdgF-BsDPHgPu8DqySrBEYTgpkSGnBg4Sp2nwV2uOydv6H2oHzjfN-Y3msI-EktinjtlcfnMgmkqnOltqsOwJxuXwQ8mukAyjdBcBQXonX1ti6bZUcSBuWZ27QOg52o_9gBfWdprilTcYwX1LfWuUqTuHMngo6riSYL_RkaDu5bCaCTTE3Xku0aUNLYNN4OV9ThtmCLGogIx1R2FxMu3FbpEDOKoAg51w1EmminXegIm0b9sytBQ",
            "e": "AQAB",
            "kid": "OTRDQ0E5MTFEMzdFMzBERDU2RUQzQjBENzVEOEUxRDM1QUU5RUZCQQ",
            "x5t": "OTRDQ0E5MTFEMzdFMzBERDU2RUQzQjBENzVEOEUxRDM1QUU5RUZCQQ"
        }
    ]
}


class Auth0Middleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        # GET TOKEN
        auth = request.META.get('HTTP_AUTHORIZATION')

        if not auth:
            return JsonResponse(data={"code": "authorization_header_missing",
                                      "description":
                                          "Authorization header is expected"}, status=401)

        parts = auth.split()

        if parts[0].lower() != "bearer":
            return JsonResponse(data={"code": "invalid_header",
                                      "description":
                                          "Authorization header must start with"
                                          "Bearer"}, status=401)
        elif len(parts) == 1:
            return JsonResponse(data={"code": "invalid_header",
                                      "description": "Token not found"}, status=401)
        elif len(parts) > 2:
            return JsonResponse(data={"code": "invalid_header",
                                      "description": "Authorization header must be"
                                                     "Bearer token"}, status=401)

        token = parts[1]
        # print(token)

        # VALIDATE TOKEN

        jwks = AUTH0_PUBLIC_KEY
        try:
            unverified_header = jwt.get_unverified_header(token)
            print(unverified_header)
        except jwt.JWTError:

            return JsonResponse(data={"code": "invalid_header",
                                      "description": "Invalid header. "
                                                     "Use an RS256 signed JWT Access Token"}, status=401)

        if unverified_header["alg"] == "HS256":
            return JsonResponse(data={"code": "invalid_header",
                                      "description": "Invalid header. "
                                                     "Use an RS256 signed JWT Access Token"}, status=401)

        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer="https://" + AUTH0_DOMAIN + "/"
                )

            except jwt.ExpiredSignatureError:
                return JsonResponse(data={"code": "token_expired",
                                          "description": "token is expired"}, status=401)
            except jwt.JWTClaimsError:
                return JsonResponse(data={"code": "invalid_claims",
                                          "description": "incorrect claims,"
                                                         " please check the audience and issuer"}, status=401)
            except Exception as ex:
                print(ex)
                return JsonResponse(data={"code": "invalid_header",
                                          "description": "Unable to parse authentication"
                                                         " token."}, status=400)
        else:
            print(rsa_key)
            return JsonResponse(data={"code": "invalid_header",
                                      "description": "Unable to find appropriate key"}, status=401)

        response = self.get_response(request)
        return response
