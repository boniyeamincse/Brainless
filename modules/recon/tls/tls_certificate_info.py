import ssl
import socket

class Module:
    @staticmethod
    def meta():
        return {
            "name": "recon/tls/tls_certificate_info",
            "description": "Retrieves TLS certificate information from a server.",
            "author": "Brainless Team",
            "tags": ["recon", "tls", "certificate", "safe"]
        }

    @staticmethod
    def default_options():
        return {
            "RHOST": "",
            "RPORT": "443",
            "TIMEOUT": "5"
        }

    @staticmethod
    def validate(opts):
        if not opts.get("RHOST"):
            return False, "RHOST is required"
        try:
            int(opts.get("RPORT", "443"))
            float(opts.get("TIMEOUT", "5"))
        except ValueError:
            return False, "RPORT must be int and TIMEOUT must be number"
        return True, "OK"

    def run(self, opts, context=None):
        ok, msg = self.validate(opts)
        if not ok:
            return {"ok": False, "error": msg}

        host = opts["RHOST"]
        port = int(opts["RPORT"])
        timeout = float(opts["TIMEOUT"])

        cert_info = {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cert_info = {
                        "subject": cert.get("subject", []),
                        "issuer": cert.get("issuer", []),
                        "version": cert.get("version"),
                        "serialNumber": str(cert.get("serialNumber")),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter")
                    }
        except Exception as e:
            return {"ok": False, "error": str(e), "host": host, "port": port}

        findings = {"certificate": cert_info}
        return {
            "ok": True,
            "host": host,
            "port": port,
            "findings": findings,
            "note": "TLS certificate info retrieved."
        }