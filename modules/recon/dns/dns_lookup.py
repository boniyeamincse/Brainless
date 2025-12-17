import socket

class Module:
    @staticmethod
    def meta():
        return {
            "name": "recon/dns/dns_lookup",
            "description": "Performs DNS lookup to resolve hostname to IP address.",
            "author": "Brainless Team",
            "tags": ["recon", "dns", "lookup", "safe"]
        }

    @staticmethod
    def default_options():
        return {
            "DOMAIN": "",
            "TIMEOUT": "5"
        }

    @staticmethod
    def validate(opts):
        if not opts.get("DOMAIN"):
            return False, "DOMAIN is required"
        try:
            float(opts.get("TIMEOUT", "5"))
        except ValueError:
            return False, "TIMEOUT must be number"
        return True, "OK"

    def run(self, opts, context=None):
        ok, msg = self.validate(opts)
        if not ok:
            return {"ok": False, "error": msg}

        domain = opts["DOMAIN"]
        timeout = float(opts["TIMEOUT"])

        ip = ""
        try:
            ip = socket.gethostbyname(domain)
        except Exception as e:
            return {"ok": False, "error": str(e), "domain": domain}

        findings = {"ip_address": ip}
        return {
            "ok": True,
            "domain": domain,
            "findings": findings,
            "note": "DNS lookup successful."
        }