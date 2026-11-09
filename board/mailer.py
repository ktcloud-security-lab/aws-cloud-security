import os
from urllib.parse import urlencode, urlsplit


def public_link(path, raw_token):
    base = os.environ.get('PUBLIC_BASE_URL', '').rstrip('/')
    parsed = urlsplit(base)
    allowed = parsed.scheme == 'https' or (
        parsed.scheme == 'http' and os.environ.get('AUTH_ALLOW_HTTP') == '1')
    if not allowed or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ValueError('Set PUBLIC_BASE_URL to an HTTPS origin; HTTP requires AUTH_ALLOW_HTTP=1 for lab use.')
    return base + path + '?' + urlencode({'token': raw_token})
