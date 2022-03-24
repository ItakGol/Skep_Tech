import typing
from urllib.parse import parse_qs, quote, unquote, urlencode, urljoin

import idna

from ._types import PrimitiveData, QueryParamTypes, URLTypes
from ._urlparse import urlparse
from ._utils import primitive_value_to_str


class URL:
    """
    url = httpx.URL("HTTPS://jo%40email.com:a%20secret@müller.de:1234/pa%20th?search=ab#anchorlink")

    assert url.scheme == "https"
    assert url.username == "jo@email.com"
    assert url.password == "a secret"
    assert url.userinfo == b"jo%40email.com:a%20secret"
    assert url.host == "müller.de"
    assert url.raw_host == b"xn--mller-kva.de"
    assert url.port == 1234
    assert url.netloc == b"xn--mller-kva.de:1234"
    assert url.path == "/pa th"
    assert url.query == b"?search=ab"
    assert url.raw_path == b"/pa%20th?search=ab"
    assert url.fragment == "anchorlink"

    The components of a URL are broken down like this:

       https://jo%40email.com:a%20secret@müller.de:1234/pa%20th?search=ab#anchorlink
    [scheme]   [  username  ] [password] [ host ][port][ path ] [ query ] [fragment]
               [       userinfo        ] [   netloc   ][    raw_path    ]

    Note that:

    * `url.scheme` is normalized to always be lowercased.

    * `url.host` is normalized to always be lowercased. Internationalized domain
      names are represented in unicode, without IDNA encoding applied. For instance:

      url = httpx.URL("http://中国.icom.museum")
      assert url.host == "中国.icom.museum"
      url = httpx.URL("http://xn--fiqs8s.icom.museum")
      assert url.host == "中国.icom.museum"

    * `url.raw_host` is normalized to always be lowercased, and is IDNA encoded.

      url = httpx.URL("http://中国.icom.museum")
      assert url.raw_host == b"xn--fiqs8s.icom.museum"
      url = httpx.URL("http://xn--fiqs8s.icom.museum")
      assert url.raw_host == b"xn--fiqs8s.icom.museum"

    * `url.port` is either None or an integer. URLs that include the default port for
      "http", "https", "ws", "wss", and "ftp" schemes have their port normalized to `None`.

      assert httpx.URL("http://example.com") == httpx.URL("http://example.com:80")
      assert httpx.URL("http://example.com").port is None
      assert httpx.URL("http://example.com:80").port is None

    * `url.userinfo` is raw bytes, without URL escaping. Usually you'll want to work with
      `url.username` and `url.password` instead, which handle the URL escaping.

    * `url.raw_path` is raw bytes of both the path and query, without URL escaping.
      This portion is used as the target when constructing HTTP requests. Usually you'll
      want to work with `url.path` instead.

    * `url.query` is raw bytes, without URL escaping. A URL query string portion can only
      be properly URL escaped when decoding the parameter names and values themselves.
    """

    def __init__(
        self, url: typing.Union["URL", str] = "", **kwargs: typing.Any
    ) -> None:
        if isinstance(url, str):
            if kwargs:
                allowed = {
                    "scheme": str,
                    "username": str,
                    "password": str,
                    "userinfo": bytes,
                    "host": str,
                    "port": int,
                    "path": str,
                    "query": bytes,
                    "fragment": str,
                    "params": object,
                }

                # Perform type checking for all supported keyword arguments.
                for key, value in kwargs.items():
                    if key not in allowed:
                        message = f"{key!r} is an invalid keyword argument."
                        raise TypeError(message)
                    if value is not None and not isinstance(value, allowed[key]):
                        expected = allowed[key].__name__
                        seen = type(value).__name__
                        message = f"Argument {key!r} must be {expected} but got {seen}."
                        raise TypeError(message)

                # The 'query' argument should be provided as bytes to match `url.query`,
                # but internally we want it as a string here.
                if "query" in kwargs and kwargs["query"] is not None:
                    kwargs["query"] = kwargs["query"].decode("ascii")

                # The 'userinfo' argument should be provided as bytes to match `url.userinfo`,
                # but internally we want it as a string here.
                if "userinfo" in kwargs and kwargs["userinfo"] is not None:
                    kwargs["userinfo"] = kwargs["userinfo"].decode("ascii")

                # The 'port' argument should be coerced to str for the purposes
                # of our internal parsing.
                if "port" in kwargs and kwargs["port"] is not None:
                    kwargs["port"] = str(kwargs["port"])

                # IPv6 hosts need to be enclosed within square brackets.
                if (
                    kwargs.get("host")
                    and ":" in kwargs["host"]
                    and not kwargs["host"].startswith("[")
                ):
                    kwargs["host"] = "[" + kwargs["host"] + "]"

                # The 'username' and 'password' keyword arguments need to be coerced
                # into a single 'userinfo'.
                if "username" in kwargs or "password" in kwargs:
                    username = quote(kwargs.pop("username", "") or "")
                    password = quote(kwargs.pop("password", "") or "")
                    kwargs["userinfo"] = (
                        f"{username}:{password}" if password else username
                    )

                # The 'params' keyword argument needs to be coerced to 'query'.
                if "params" in kwargs:
                    params = kwargs.pop("params")
                    kwargs["query"] = (
                        None if params is None else str(QueryParams(params))
                    )

            self._parsed = urlparse(url, **kwargs)
        elif isinstance(url, URL):
            self._parsed = url._parsed
        else:
            raise TypeError(
                f"Invalid type for url.  Expected str or httpx.URL, got {type(url)}: {url!r}"
            )

    @property
    def scheme(self) -> str:
        """
        The URL scheme, such as "http", "https".
        Always normalised to lowercase.
        """
        return self._parsed.scheme.decode("ascii")

    @property
    def raw_scheme(self) -> bytes:
        """
        The raw bytes representation of the URL scheme, such as b"http", b"https".
        Always normalised to lowercase.
        """
        return self._parsed.scheme

    @property
    def userinfo(self) -> bytes:
        """
        The URL userinfo as a raw bytestring.
        For example: b"jo%40email.com:a%20secret".
        """
        return self._parsed.userinfo

    @property
    def username(self) -> str:
        """
        The URL username as a string, with URL decoding applied.
        For example: "jo@email.com"
        """
        userinfo: bytes = self._parsed.userinfo
        return unquote(userinfo.decode("ascii").partition(":")[0])

    @property
    def password(self) -> str:
        """
        The URL password as a string, with URL decoding applied.
        For example: "a secret"
        """
        userinfo: bytes = self._parsed.userinfo
        return unquote(userinfo.decode("ascii").partition(":")[2])

    @property
    def host(self) -> str:
        """
        The URL host as a string.
        Always normalized to lowercase, with IDNA hosts decoded into unicode.

        Examples:

        url = httpx.URL("http://www.EXAMPLE.org")
        assert url.host == "www.example.org"

        url = httpx.URL("http://中国.icom.museum")
        assert url.host == "中国.icom.museum"

        url = httpx.URL("http://xn--fiqs8s.icom.museum")
        assert url.host == "中国.icom.museum"

        url = httpx.URL("https://[::ffff:192.168.0.1]")
        assert url.host == "::ffff:192.168.0.1"
        """
        host: bytes = self._parsed.host

        if host.startswith(b"xn--"):
            return idna.decode(host)
        elif host.startswith(b"[") and host.endswith(b"]"):
            return host.decode("ascii").lstrip("[").rstrip("]")
        return host.decode("ascii")

    @property
    def raw_host(self) -> bytes:
        """
        The raw bytes representation of the URL host.
        Always normalized to lowercase, and IDNA encoded.

        Examples:

        url = httpx.URL("http://www.EXAMPLE.org")
        assert url.raw_host == b"www.example.org"

        url = httpx.URL("http://中国.icom.museum")
        assert url.raw_host == b"xn--fiqs8s.icom.museum"

        url = httpx.URL("http://xn--fiqs8s.icom.museum")
        assert url.raw_host == b"xn--fiqs8s.icom.museum"

        url = httpx.URL("https://[::ffff:192.168.0.1]")
        assert url.raw_host == b"::ffff:192.168.0.1"
        """
        host: bytes = self._parsed.host

        if host.startswith(b"[") and host.endswith(b"]"):
            return host.lstrip(b"[").rstrip(b"]")
        return host

    @property
    def port(self) -> typing.Optional[int]:
        """
        The URL port as an integer.

        Note that the URL class performs port normalization as per the WHATWG spec.
        Default ports for "http", "https", "ws", "wss", and "ftp" schemes are always
        treated as `None`.

        For example:

        assert httpx.URL("http://www.example.com") == httpx.URL("http://www.example.com:80")
        assert httpx.URL("http://www.example.com:80").port is None
        """
        return self._parsed.port

    @property
    def netloc(self) -> bytes:
        """
        Either `<host>` or `<host>:<port>` as bytes.
        Always normalized to lowercase, and IDNA encoded.

        This property may be used for generating the value of a request
        "Host" header.
        """
        host: bytes = self._parsed.host
        port: typing.Optional[int] = self._parsed.port

        netloc = host
        if b":" in netloc:
            netloc = b"[" + netloc + b"]"
        if port:
            netloc = netloc + b":" + str(port).encode("ascii")
        return netloc

    @property
    def path(self) -> str:
        """
        The URL path as a string. Excluding the query string, and URL decoded.

        For example:

        url = httpx.URL("https://example.com/pa%20th")
        assert url.path == "/pa th"
        """
        return unquote(self._parsed.path.decode("ascii")) or "/"

    @property
    def query(self) -> bytes:
        """
        The URL query string, as raw bytes, excluding the leading b"?".

        This is necessarily a bytewise interface, because we cannot
        perform URL decoding of this representation until we've parsed
        the keys and values into a QueryParams instance.

        For example:

        url = httpx.URL("https://example.com/?filter=some%20search%20terms")
        assert url.query == b"filter=some%20search%20terms"
        """
        return self._parsed.query or b""

    @property
    def params(self) -> "QueryParams":
        """
        The URL query parameters, neatly parsed and packaged into an immutable
        multidict representation.
        """
        return QueryParams(self._parsed.query)

    @property
    def raw_path(self) -> bytes:
        """
        The complete URL path and query string as raw bytes.
        Used as the target when constructing HTTP requests.

        For example:

        GET /users?search=some%20text HTTP/1.1
        Host: www.example.org
        Connection: close
        """
        raw_path = self._parsed.path or b"/"
        if self._parsed.query is not None:
            raw_path += b"?" + self._parsed.query
        return raw_path

    @property
    def fragment(self) -> str:
        """
        The URL fragments, as used in HTML anchors.
        As a string, without the leading '#'.
        """
        fragment = self._parsed.fragment or b""

        return unquote(fragment.decode("ascii"))

    @property
    def is_absolute_url(self) -> bool:
        """
        Return `True` for absolute URLs such as 'http://example.com/path',
        and `False` for relative URLs such as '/path'.
        """
        # We don't use `.is_absolute` from `rfc3986` because it treats
        # URLs with a fragment portion as not absolute.
        # What we actually care about is if the URL provides
        # a scheme and hostname to which connections should be made.
        return bool(self._parsed.scheme and self._parsed.host)

    @property
    def is_relative_url(self) -> bool:
        """
        Return `False` for absolute URLs such as 'http://example.com/path',
        and `True` for relative URLs such as '/path'.
        """
        return not self.is_absolute_url

    def copy_with(self, **kwargs: typing.Any) -> "URL":
        """
        Copy this URL, returning a new URL with some components altered.
        Accepts the same set of parameters as the components that are made
        available via properties on the `URL` class.

        For example:

        url = httpx.URL("https://www.example.com").copy_with(username="jo@gmail.com", password="a secret")
        assert url == "https://jo%40email.com:a%20secret@www.example.com"
        """
        allowed = {
            "scheme": str,
            "username": str,
            "password": str,
            "userinfo": bytes,
            "host": str,
            "port": int,
            "path": str,
            "query": bytes,
            "fragment": str,
            "params": object,
        }

        # Perform type checking for all supported keyword arguments.
        for key, value in kwargs.items():
            if key not in allowed:
                message = f"{key!r} is an invalid keyword argument."
                raise TypeError(message)
            if value is not None and not isinstance(value, allowed[key]):
                expected = allowed[key].__name__
                seen = type(value).__name__
                message = f"Argument {key!r} must be {expected} but got {seen}."
                raise TypeError(message)

        # Merge the provided keyword arguments with the existing URL.
        init_kwargs = {
            "scheme": kwargs.get("scheme", self.scheme),
            "userinfo": kwargs.get("userinfo", self.userinfo),
            "host": kwargs.get("host", self.host),
            "port": kwargs.get("port", self.port),
            "path": kwargs.get("path", unquote(self._parsed.path.decode("ascii"))),
            "query": kwargs.get("query", self.query or None),
            "fragment": kwargs.get("fragment", self.fragment or None),
        }

        # Consolidate any conflicting keyword arguments.
        if "username" in kwargs or "password" in kwargs:
            init_kwargs["username"] = kwargs.get("username", self.username)
            init_kwargs["password"] = kwargs.get("password", self.password)
            init_kwargs.pop("userinfo")

        if "params" in kwargs:
            init_kwargs["params"] = kwargs["params"]
            init_kwargs.pop("query")

        # Build a new URL with the merged components.
        return URL(**init_kwargs)

    def copy_set_param(self, key: str, value: typing.Any = None) -> "URL":
        return self.copy_with(params=self.params.set(key, value))

    def copy_add_param(self, key: str, value: typing.Any = None) -> "URL":
        return self.copy_with(params=self.params.add(key, value))

    def copy_remove_param(self, key: str) -> "URL":
        params = self.params.remove(key)
        return self.copy_with(params=None if not params else params)

    def copy_merge_params(self, params: QueryParamTypes) -> "URL":
        params = self.params.merge(params)
        return self.copy_with(params=None if not params else params)

    def join(self, url: URLTypes) -> "URL":
        """
        Return an absolute URL, using this URL as the base.

        Eg.

        url = httpx.URL("https://www.example.com/test")
        url = url.join("/new/path")
        assert url == "https://www.example.com/new/path"
        """
        other = URL(url)
        return URL(urljoin(str(self), str(other)))

    def _to_string(self, mask_password: bool = False) -> str:
        url = ""
        if self._parsed.scheme:
            url += self._parsed.scheme.decode("ascii") + ":"
        if self._parsed.userinfo or self._parsed.host or self._parsed.port:
            url += "//"
            if self._parsed.userinfo:
                if mask_password and self.password:
                    url += quote(self.username) + ":[secure]@"
                else:
                    url += self._parsed.userinfo.decode("ascii") + "@"
            if self._parsed.host:
                if b":" in self._parsed.host:
                    url += "[" + self._parsed.host.decode("ascii") + "]"
                else:
                    url += self._parsed.host.decode("ascii")
            if self._parsed.port:
                url += ":" + str(self._parsed.port)
        if self._parsed.path:
            url += self._parsed.path.decode("ascii")
        if self._parsed.query is not None:
            url += "?" + self._parsed.query.decode("ascii")
        if self._parsed.fragment is not None:
            url += "#" + self._parsed.fragment.decode("ascii")
        return url

    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, other: typing.Any) -> bool:
        return isinstance(other, (URL, str)) and str(self) == str(URL(other))

    def __str__(self) -> str:
        return self._to_string()

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        url_str = self._to_string(mask_password=True)
        return f"{class_name}({url_str!r})"


class QueryParams(typing.Mapping[str, str]):
    """
    URL query parameters, as a multi-dict.
    """

    def __init__(self, *args: QueryParamTypes, **kwargs: typing.Any) -> None:
        assert len(args) < 2, "Too many arguments."
        assert not (args and kwargs), "Cannot mix named and unnamed arguments."

        value = args[0] if args else kwargs

        items: typing.Sequence[typing.Tuple[str, PrimitiveData]]
        if value is None or isinstance(value, (str, bytes)):
            value = value.decode("ascii") if isinstance(value, bytes) else value
            self._dict = parse_qs(value)
        elif isinstance(value, QueryParams):
            self._dict = {k: list(v) for k, v in value._dict.items()}
        else:
            dict_value: typing.Dict[typing.Any, typing.List[typing.Any]] = {}
            if isinstance(value, (list, tuple)):
                # Convert list inputs like:
                #     [("a", "123"), ("a", "456"), ("b", "789")]
                # To a dict representation, like:
                #     {"a": ["123", "456"], "b": ["789"]}
                for item in value:
                    dict_value.setdefault(item[0], []).append(item[1])
            else:
                # Convert dict inputs like:
                #    {"a": "123", "b": ["456", "789"]}
                # To dict inputs where values are always lists, like:
                #    {"a": ["123"], "b": ["456", "789"]}
                dict_value = {
                    k: list(v) if isinstance(v, (list, tuple)) else [v]
                    for k, v in value.items()
                }

            # Ensure that keys and values are neatly coerced to strings.
            # We coerce values `True` and `False` to JSON-like "true" and "false"
            # representations, and coerce `None` values to the empty string.
            self._dict = {
                str(k): [primitive_value_to_str(item) for item in v]
                for k, v in dict_value.items()
            }

    def keys(self) -> typing.KeysView:
        """
        Return all the keys in the query params.

        Usage:

        q = httpx.QueryParams("a=123&a=456&b=789")
        assert list(q.keys()) == ["a", "b"]
        """
        return self._dict.keys()

    def values(self) -> typing.ValuesView:
        """
        Return all the values in the query params. If a key occurs more than once
        only the first item for that key is returned.

        Usage:

        q = httpx.QueryParams("a=123&a=456&b=789")
        assert list(q.values()) == ["123", "789"]
        """
        return {k: v[0] for k, v in self._dict.items()}.values()

    def items(self) -> typing.ItemsView:
        """
        Return all items in the query params. If a key occurs more than once
        only the first item for that key is returned.

        Usage:

        q = httpx.QueryParams("a=123&a=456&b=789")
        assert list(q.items()) == [("a", "123"), ("b", "789")]
        """
        return {k: v[0] for k, v in self._dict.items()}.items()

    def multi_items(self) -> typing.List[typing.Tuple[str, str]]:
        """
        Return all items in the query params. Allow duplicate keys to occur.

        Usage:

        q = httpx.QueryParams("a=123&a=456&b=789")
        assert list(q.multi_items()) == [("a", "123"), ("a", "456"), ("b", "789")]
        """
        multi_items: typing.List[typing.Tuple[str, str]] = []
        for k, v in self._dict.items():
            multi_items.extend([(k, i) for i in v])
        return multi_items

    def get(self, key: typing.Any, default: typing.Any = None) -> typing.Any:
        """
        Get a value from the query param for a given key. If the key occurs
        more than once, then only the first value is returned.

        Usage:

        q = httpx.QueryParams("a=123&a=456&b=789")
        assert q.get("a") == "123"
        """
        if key in self._dict:
            return self._dict[str(key)][0]
        return default

    def get_list(self, key: str) -> typing.List[str]:
        """
        Get all values from the query param for a given key.

        Usage:

        q = httpx.QueryParams("a=123&a=456&b=789")
        assert q.get_list("a") == ["123", "456"]
        """
        return list(self._dict.get(str(key), []))

    def set(self, key: str, value: typing.Any = None) -> "QueryParams":
        """
        Return a new QueryParams instance, setting the value of a key.

        Usage:

        q = httpx.QueryParams("a=123")
        q = q.set("a", "456")
        assert q == httpx.QueryParams("a=456")
        """
        q = QueryParams()
        q._dict = dict(self._dict)
        q._dict[str(key)] = [primitive_value_to_str(value)]
        return q

    def add(self, key: str, value: typing.Any = None) -> "QueryParams":
        """
        Return a new QueryParams instance, setting or appending the value of a key.

        Usage:

        q = httpx.QueryParams("a=123")
        q = q.add("a", "456")
        assert q == httpx.QueryParams("a=123&a=456")
        """
        q = QueryParams()
        q._dict = dict(self._dict)
        q._dict[str(key)] = q.get_list(key) + [primitive_value_to_str(value)]
        return q

    def remove(self, key: str) -> "QueryParams":
        """
        Return a new QueryParams instance, removing the value of a key.

        Usage:

        q = httpx.QueryParams("a=123")
        q = q.remove("a")
        assert q == httpx.QueryParams("")
        """
        q = QueryParams()
        q._dict = dict(self._dict)
        q._dict.pop(str(key), None)
        return q

    def merge(self, params: QueryParamTypes = None) -> "QueryParams":
        """
        Return a new QueryParams instance, updated with.

        Usage:

        q = httpx.QueryParams("a=123")
        q = q.merge({"b": "456"})
        assert q == httpx.QueryParams("a=123&b=456")

        q = httpx.QueryParams("a=123")
        q = q.merge({"a": "456", "b": "789"})
        assert q == httpx.QueryParams("a=456&b=789")
        """
        q = QueryParams(params)
        q._dict = {**self._dict, **q._dict}
        return q

    def __getitem__(self, key: typing.Any) -> str:
        return self._dict[key][0]

    def __contains__(self, key: typing.Any) -> bool:
        return key in self._dict

    def __iter__(self) -> typing.Iterator[typing.Any]:
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self._dict)

    def __bool__(self) -> bool:
        return bool(self._dict)

    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return sorted(self.multi_items()) == sorted(other.multi_items())

    def __str__(self) -> str:
        return urlencode(self.multi_items())

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        query_string = str(self)
        return f"{class_name}({query_string!r})"

    def update(self, params: QueryParamTypes = None) -> None:
        raise RuntimeError(
            "QueryParams are immutable since 0.18.0. "
            "Use `q = q.merge(...)` to create an updated copy."
        )

    def __setitem__(self, key: str, value: str) -> None:
        raise RuntimeError(
            "QueryParams are immutable since 0.18.0. "
            "Use `q = q.set(key, value)` to create an updated copy."
        )
