from .compat import compat_cookiejar, compat_pickle

_cookie_attrs = dict(
    version=0, name="", value="",
    port=None, domain='', path='/',
    secure=False, expires=None, discard=True,
    comment=None, comment_url=None,
    rfc2109=False,
)
_bool_attrs = (
    ('port_specified', lambda c: bool(c['port'])),
    ('domain_specified', lambda c: bool(c['domain'])),
    ('domain_initial_dot', lambda c: c['domain'].startswith('.')),
    ('path_specified', lambda c: bool(c['path'])),
)


class ClientCookieJar(compat_cookiejar.CookieJar):
    """
    Custom CookieJar that can be pickled to/from bytestrings or dicts
    """
    @staticmethod
    def cookie_to_dict(cookie):
        dct = {}
        for attr in _cookie_attrs:
            val = getattr(cookie, attr)
            if val == _cookie_attrs[attr]:
                # don't store default values
                continue
            dct[attr] = getattr(cookie, attr)
        if cookie._rest:
            dct['rest'] = cookie._rest
        return dct

    @staticmethod
    def cookie_from_dict(dct):
        """
        Constructs a cookie from a dict.

        Fills in any missing parameters from a set of defaults.

        This method was based on Requests' "create_cookie"
        function, originally written by Miguel Turner (dhagrow):
        https://github.com/dhagrow/requests/blame/develop/requests/packages/oreos/cookiejar.py#L126
        """
        if 'name' not in dct or 'value' not in dct:
            raise TypeError('Cookie dictionary must contain name and value')

        cookie_kwargs = _cookie_attrs.copy()
        cookie_kwargs['rest'] = {}

        extra_args = set(dct) - set(cookie_kwargs)
        if extra_args:
            err = 'Unexpected keys in Cookie dictionary: {}'
            raise TypeError(err.format(sorted(extra_args)))

        cookie_kwargs.update(dct)
        for key, func in _bool_attrs:
            cookie_kwargs[key] = func(cookie_kwargs)

        return compat_cookiejar.Cookie(**cookie_kwargs)

    def __init__(self, cookie_repr=None, policy=None):
        compat_cookiejar.CookieJar.__init__(self, policy)
        self._format = "pickle"
        if isinstance(cookie_repr, dict):
            self._format = "dict"
            self.set_cookies_from_dict(cookie_repr)
        elif cookie_repr:
            self._cookies = compat_pickle.loads(cookie_repr.encode('utf-8'))

    @property
    def format(self):
        return self._format

    @format.setter
    def format(self, new_format):
        if new_format in ('dict', 'json', 'pickle', 'str', 'bytes'):
            self._format = new_format

    def set_cookies_from_dict(self, cookie_dict, overwrite=True, domain=None, path=None):
        """
        A dictionary of cookies, optionally nested by domain and/or path

        If overwrite, overwrites existing cookies.

        domain and path are only used during recursion

        May raise TypeError if cookie_dict is invalid or contains unexpected keys
        """
        if not cookie_dict:
            return
        existing_names = [cookie.name for cookie in self]

        for key in cookie_dict:
            # will fail if path or cookie.name == 'name'
            # as is, this check allows mixed nesting
            # e.g. cookies and domains at the same level
            if 'name' not in cookie_dict[key]:
                if domain is not None:
                    if path is not None:
                        err = 'No Cookies found in dictionary'
                        raise TypeError(err)
                    else:
                        self.set_cookies_from_dict(cookie_dict[key],
                                                   domain=domain,
                                                   path=key)
                else:
                    self.set_cookies_from_dict(cookie_dict[key],
                                               domain=domain)
            else:
                if overwrite or key not in existing_names:
                    self.set_cookie(self.cookie_from_dict(cookie_dict[key]))

    @property
    def expires_earliest(self):
        return min([cookie.expires for cookie in self], default=None)

    def dump(self, use_format=None):
        """
        Dumps contents of CookieJar for saving to file.

        If use_format is "dict" or "json", or if this CookieJar
        was created using a dict as the cookie_repr,
        this method will return a similar dict.

        Otherwise pickles and returns its contents.
        """
        if (use_format or self._format) in ("dict", "json"):
            return self.to_dict()
        else:
            return compat_pickle.dumps(self._cookies)

    def to_dict(self, ignore_domain=False, ignore_path=False):
        """
        Returns a dict representation of the CookieJar

        If more than one domain exists, or more than one path in
        each domain, cookies will be nested under their respective
        domain/path. Otherwise all cookies will be stored at the
        topmost level.

        Nesting can be disabled with ignore_domain and ignore_path

        Examples:

            One domain, one path:
            {
                cookie1.name: {key: val, ...},
                cookie2.name: {key: val, ...},
                ...
            }

            Multiple domains, one path per domain:
            {
                domain1: {
                    cookie1.name: {key: val, ...},
                    ...
                },
                domain2: {
                    cookie1.name: {key: val, ...},
                    ...
                },
                ...
            }

            One domain, multiple paths:
            {
                path1: {
                    cookie1.name: {key: val, ...},
                    ...
                },
                path2: {
                    cookie1.name: {key: val, ...},
                    ...
                },
                ...
            }

            Multiple domains, multiple paths per domain:
            {
                domain1: {
                    path1: {
                        cookie1.name: {key: val, ...},
                        ...
                    },
                    ...
                },
                ...
            }

        set_cookies_from_dict can handle any of the above variants.
        """
        target = cookie_dict = {}

        if not ignore_domain and len(self._cookies) > 1:
            nest_domain = True
        else:
            nest_domain = False

        for domain in self._cookies:
            if nest_domain:
                target = cookie_dict[domain] = {}

            if not ignore_path and len(self._cookies[domain]) > 1:
                nest_path = True
            else:
                nest_path = False

            for path in self._cookies[domain]:
                if nest_path:
                    target = target[path] = {}

                for name in self._cookies[domain][path]:
                    cookie = self._cookies[domain][path][name]
                    target[name] = self.cookie_to_dict(cookie)
        return cookie_dict
