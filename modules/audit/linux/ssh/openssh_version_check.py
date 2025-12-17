import socket

class Module:
    @staticmethod
    def meta():
        return {
            "name": "audit/linux/ssh/openssh_version_check",
            "description": "Checks SSH banner and reports detected OpenSSH version (no exploitation).",
            "author": "Brainless Team",
            "tags": ["audit", "ssh", "version", "safe"]
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

        # Example banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        findings = {"ssh_banner": banner}
        return {
            "ok": True,
            "host": host,
            "port": port,
            "findings": findings,
            "note": "Banner-based identification only; verify with authenticated methods if needed."
        }