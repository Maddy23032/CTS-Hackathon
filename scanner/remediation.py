def generate_remediation(vuln_type, details):
    if vuln_type == "SQL Injection":
        payload = details.get("payload", "unknown payload")
        field = details.get("field_name", "the input field")
        return (
            f"Prevent SQL Injection by sanitizing and parameterizing '{field}'. "
            f"Detected injection attempt using payload: {payload}. Use prepared statements."
        )
    if vuln_type == "XSS":
        field = details.get("field_name", "the input field")
        return (
            f"Prevent XSS by sanitizing and encoding output from '{field}'. "
            "Malicious scripts reflected in response."
        )
    if vuln_type == "CSRF":
        url = details.get("url", "this form")
        return (
            f"Add and validate CSRF tokens server-side in your POST forms like '{url}' "
            "to prevent forgery attacks."
        )
    return "Apply security best practices based on vulnerability."
