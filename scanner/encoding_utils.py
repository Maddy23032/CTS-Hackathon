import urllib.parse
import html

def url_encode(payload):
    return urllib.parse.quote(payload)

def html_encode(payload):
    return html.escape(payload)

def double_url_encode(payload):
    return urllib.parse.quote(urllib.parse.quote(payload))
