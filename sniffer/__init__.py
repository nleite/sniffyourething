
class TwitterCredentials(object):
    """
    Holds the information on the different twitter api crentials like:
        - consumer_key
        - consumer_scret
        - access_token_key
        - access_token_secret
    according with twitter docs https://dev.twitter.com/overview/documentation
    """

    def __init__(self, CK, CS, AK, AS):
        self._cs = CS
        self._ck = CK
        self._ak = AK
        self._as = AS

    @property
    def consumer_key(self):
        return self._ck

    @property
    def consumer_secret(self):
        return self._cs

    @property
    def access_token_secret(self):
        return self._as

    @property
    def access_token_key(self):
        return self._ak

    def all(self):
        return( self._ck, self._cs, self._ak, self._as)
