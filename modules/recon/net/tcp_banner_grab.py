import socket

class Module:
    @staticmethod
    def meta():
        return {
            "name": "recon/net/tcp_banner_grab",
            "description": "Grabs banners from TCP services for reconnaissance.",
            "author": "Brainless Team",
            "tags": ["recon", "tcp", "banner", "safe"]
        }

    @staticmethod
    def default_options():
        return {
            "RHOST": "",
            "RPORT": "22",
            "TIMEOUT": "5"
        }

    @staticmethod
    def validate(opts):
        if not opts.get("RHOST"):
            return False, "RHOST is required"
        try:
            int(opts.get("RPORT", "22"))
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

        banner = ""
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                banner = s.recv(256).decode(errors="replace").strip()
        except Exception as e:
            return {"ok": False, "error": str(e), "host": host, "port": port}

        findings = {"banner": banner}
        return {
            "ok": True,
            "host": host,
            "port": port,
            "findings": findings,
            "note": "Banner grabbed successfully."
        }