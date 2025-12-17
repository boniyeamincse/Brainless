import urllib.request
import urllib.error

class Module:
    @staticmethod
    def meta():
        return {
            "name": "recon/http/http_headers",
            "description": "Retrieves HTTP headers from a web server.",
            "author": "Brainless Team",
            "tags": ["recon", "http", "headers", "safe"]
        }

    @staticmethod
    def default_options():
        return {
            "URL": "",
            "TIMEOUT": "5"
        }

    @staticmethod
    def validate(opts):
        if not opts.get("URL"):
            return False, "URL is required"
        try:
            float(opts.get("TIMEOUT", "5"))
        except ValueError:
            return False, "TIMEOUT must be number"
        return True, "OK"

    def run(self, opts, context=None):
        ok, msg = self.validate(opts)
        if not ok:
            return {"ok": False, "error": msg}

        url = opts["URL"]
        timeout = float(opts["TIMEOUT"])

        headers = {}
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                headers = dict(response.headers)
        except Exception as e:
            return {"ok": False, "error": str(e), "url": url}

        findings = {"headers": headers}
        return {
            "ok": True,
            "url": url,
            "findings": findings,
            "note": "HTTP headers retrieved."
        }