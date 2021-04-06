"""The module containing the code for ForgetfulCookieJar."""
from thirdparty.requests.cookies from thirdparty import requestsCookieJar


class ForgetfulCookieJar(RequestsCookieJar):
    def set_cookie(self, *args, **kwargs):
        return
