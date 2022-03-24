import ipaddress
import re
import typing

import idna

from ._exceptions import InvalidURL

MAX_URL_LENGTH = 8000
NOT_PERCENT_ENCODED = b"!#$&'()*+,-./0123456789:;=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]_abcdefghijklmnopqrstuvwxyz~"
PERCENT_ENCODED_REGEX = re.compile(b"%[A-Fa-f0-9]{2}")


# {scheme}:      (optional)
# //{authority}  (optional)
# {path}
# ?{query}       (optional)
# #{fragment}    (optional)
URL_REGEX = re.compile(
    (
        r"(?:(?P<scheme>{scheme}):)?"
        r"(?://(?P<authority>{authority}))?"
        r"(?P<path>{path})"
        r"(?:\?(?P<query>{query}))?"
        r"(?:#(?P<fragment>{fragment}))?"
    ).format(
        scheme="[a-zA-Z][a-zA-Z0-9+.-]*",
        authority="[^\\\\/?#]*",
        path="[^?#]*",
        query="[^#]*",
        fragment=".*",
    )
)

# {userinfo}@    (optional)
# {host}
# :{port}        (optional)
AUTHORITY_REGEX = re.compile(
    (
        r"(?:(?P<userinfo>{userinfo})@)?" r"(?P<host>{host})" r":?(?P<port>{port})?"
    ).format(userinfo="[^@]*", host="(\\[.*\\]|[^:]*)", port=".*")
)

# We use these simple regexs as a first pass before handing off to
# the stdlib 'ipaddress' module for IP address validation.
IPv4_STYLE_HOSTNAME = re.compile(r"^[0-9]+.[0-9]+.[0-9]+.[0-9]+$")
IPv6_STYLE_HOSTNAME = re.compile(r"^\[.*\]$")


class ParseResult(typing.NamedTuple):
    scheme: bytes
    userinfo: bytes
    host: bytes
    port: typing.Optional[int]
    path: bytes
    query: typing.Optional[bytes]
    fragment: typing.Optional[bytes]


def urlparse(url: str, **kwargs: typing.Optional[str]) -> ParseResult:
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURL("URL too long.")
    if "\n" in url or "\r" in url or "\t" in url:
        raise InvalidURL("Invalid character in URL.")

    for key, value in kwargs.items():
        if value is not None:
            if len(value) > MAX_URL_LENGTH:
                raise InvalidURL(f"URL component '{key}' too long.")
            if "\n" in value or "\r" in value or "\t" in value:
                raise InvalidURL(f"Invalid character in URL component '{key}'.")

    # The URL_REGEX will always match, but may have empty components.
    url_match = URL_REGEX.match(url)
    assert url_match is not None
    url_dict = url_match.groupdict()

    scheme = kwargs.get("scheme", url_dict["scheme"]) or ""
    authority = kwargs.get("authority", url_dict["authority"]) or ""
    path = kwargs.get("path", url_dict["path"]) or ""
    query = kwargs.get("query", url_dict["query"])
    fragment = kwargs.get("fragment", url_dict["fragment"])

    # The AUTHORITY_REGEX will always match, but may have empty components.
    authority_match = AUTHORITY_REGEX.match(authority)
    assert authority_match is not None
    authority_dict = authority_match.groupdict()

    userinfo = kwargs.get("userinfo", authority_dict["userinfo"]) or ""
    host = kwargs.get("host", authority_dict["host"]) or ""
    port = kwargs.get("port", authority_dict["port"])

    # Normalize and validate each component.
    # We end up with a parsed representation of the URL,
    # with components that are plain ASCII bytestrings.
    parsed_scheme: bytes = encode_scheme(scheme)
    parsed_userinfo: bytes = encode_userinfo(userinfo)
    parsed_host: bytes = encode_host(host)
    parsed_port: typing.Optional[int] = normalize_port(port, scheme)
    if scheme and host:
        path = normalize_path(path)
    parsed_path: bytes = encode_path(path)
    parsed_query: typing.Optional[bytes] = encode_query(query)
    parsed_fragment: typing.Optional[bytes] = encode_fragment(fragment)

    # The parsed ASCII bytestrings are our canonical form.
    # All properties of the URL are derived from these.
    return ParseResult(
        parsed_scheme,
        parsed_userinfo,
        parsed_host,
        parsed_port,
        parsed_path,
        parsed_query,
        parsed_fragment,
    )


def encode_scheme(scheme: str) -> bytes:
    return scheme.encode("ascii").lower()


def encode_userinfo(userinfo: str) -> bytes:
    encoded_userinfo = userinfo.encode("utf-8")
    return quote_if_needed(encoded_userinfo)


def encode_host(host: str) -> bytes:
    if not host:
        return b""

    elif IPv4_STYLE_HOSTNAME.match(host):
        # Validate hostnames like #.#.#.#
        try:
            ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError:
            raise InvalidURL("Invalid IPv4 address")
        return host.encode("ascii")

    elif IPv6_STYLE_HOSTNAME.match(host):
        # Validate hostnames like [...]
        # (IPv6 hostnames must always be enclosed within square brackets)
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ipaddress.AddressValueError:
            raise InvalidURL("Invalid IPv6 address")
        return host[1:-1].encode("ascii")

    elif all(ord(char) <= 127 for char in host):
        # Regular ASCII hostnames
        encoded_host = host.encode("ascii").lower()
        return quote_if_needed(encoded_host)

    # IDNA hostnames
    try:
        return idna.encode(host.lower())
    except idna.IDNAError:
        raise InvalidURL("Invalid IDNA hostname")


def encode_path(path: str) -> bytes:
    encoded_path = path.encode("utf-8")
    return quote_if_needed(encoded_path)


def encode_query(query: typing.Optional[str]) -> typing.Optional[bytes]:
    if query is None:
        return None

    encoded_query = query.encode("utf-8")
    return quote_if_needed(encoded_query)


def encode_fragment(fragment: typing.Optional[str]) -> typing.Optional[bytes]:
    if fragment is None:
        return None

    encoded_fragment = fragment.encode("utf-8")
    return quote_if_needed(encoded_fragment)


def normalize_port(
    port: typing.Optional[typing.Union[str, int]], scheme: str
) -> typing.Optional[int]:
    # https://tools.ietf.org/html/rfc3986#section-3.2.3
    #
    # A scheme may define a default port.  For example, the "http" scheme
    # defines a default port of "80", corresponding to its reserved TCP
    # port number.  The type of port designated by the port number (e.g.,
    # TCP, UDP, SCTP) is defined by the URI scheme.  URI producers and
    # normalizers should omit the port component and its ":" delimiter if
    # port is empty or if its value would be the same as that of the
    # scheme's default.
    if not port:
        return None

    # validate
    port_as_int = int(port)
    default_port = {"http": 80, "https": 443}.get(scheme)
    if port_as_int == default_port:
        return None
    return port_as_int


def normalize_path(path: str) -> str:
    # https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4
    components = path.split("/")
    output: typing.List[str] = []
    for component in components:
        if component == ".":
            pass
        elif component == "..":
            if output:
                output.pop()
        else:
            output.append(component)
    return "/".join(output)


def quote_if_needed(component: bytes) -> bytes:
    ESCAPED_CHARS = NOT_PERCENT_ENCODED
    if component.count(b"%") == len(PERCENT_ENCODED_REGEX.findall(component)):
        # If the component is already percent encoded,
        # then include percent as a non-escaping byte.
        ESCAPED_CHARS += b"%"

    byte_list = [component[idx : idx + 1] for idx in range(len(component))]
    return b"".join(
        [
            byte if byte in ESCAPED_CHARS else f"%{ord(byte):02x}".encode().upper()
            for byte in byte_list
        ]
    )
