from .remediation import generate_remediation

COMMON_CSRF_NAMES = [
    "csrf", "token", "authenticity_token", "x-csrf-token", "antiforgerytoken"
]

def check_csrf(form, method):
    inputs = form.find_all("input")
    has_token = False

    for inp in inputs:
        if (inp.get("type") or "").lower() == "hidden":
            name = (inp.get("name") or "").lower()
            if any(token_name in name for token_name in COMMON_CSRF_NAMES):
                has_token = True
                break

    if method == "post" and not has_token:
        details = {"url": form.get("action") or "this form"}
        return {
            "vulnerability_type": "CSRF",
            "vulnerable": True,
            "message": "Form missing CSRF token.",
            "remediation": generate_remediation("CSRF", details),
        }
    else:
        return {
            "vulnerability_type": "CSRF",
            "vulnerable": False,
            "message": "",
            "remediation": "",
        }
