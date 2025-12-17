import urllib.request
import urllib.error

class Module:
    @staticmethod
    def meta():
        return {
            "name": "audit/web/apache_version_check",
            "description": "Checks Apache version from HTTP Server header.",
            "author": "Brainless Team",
            "tags": ["audit", "web", "apache", "version", "safe"]
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

        server_header = ""
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                server_header = response.headers.get("Server", "")
        except Exception as e:
            return {"ok": False, "error": str(e), "url": url}

        findings = {"server_header": server_header}
        return {
            "ok": True,
            "url": url,
            "findings": findings,
            "note": "Server header retrieved; check for Apache version."
        }