import socket

class Module:
    @staticmethod
    def meta():
        return {
            "name": "utility/net/tcp_connect_check",
            "description": "Checks if a TCP connection can be established.",
            "author": "Brainless Team",
            "tags": ["utility", "net", "tcp", "connect", "safe"]
        }

    @staticmethod
    def default_options():
        return {
            "RHOST": "",
            "RPORT": "80",
            "TIMEOUT": "5"
        }

    @staticmethod
    def validate(opts):
        if not opts.get("RHOST"):
            return False, "RHOST is required"
        try:
            int(opts.get("RPORT", "80"))
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

        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
        except Exception as e:
            return {"ok": False, "error": str(e), "host": host, "port": port}

        return {
            "ok": True,
            "host": host,
            "port": port,
            "note": "TCP connection successful."
        }