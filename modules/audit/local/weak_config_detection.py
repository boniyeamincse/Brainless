import os

class Module:
    @staticmethod
    def meta():
        return {
            "name": "audit/local/weak_config_detection",
            "description": "Detects weak configurations in common files.",
            "author": "Brainless Team",
            "tags": ["audit", "local", "config", "weak", "safe"]
        }

    @staticmethod
    def default_options():
        return {
            "CONFIG_PATH": "/etc/ssh/sshd_config"
        }

    @staticmethod
    def validate(opts):
        if not opts.get("CONFIG_PATH"):
            return False, "CONFIG_PATH is required"
        return True, "OK"

    def run(self, opts, context=None):
        ok, msg = self.validate(opts)
        if not ok:
            return {"ok": False, "error": msg}

        config_path = opts["CONFIG_PATH"]

        if not os.path.exists(config_path):
            return {"ok": False, "error": "Config file does not exist", "config_path": config_path}

        issues = []
        try:
            with open(config_path, 'r') as f:
                content = f.read()
                # Simple checks
                if 'PermitRootLogin yes' in content:
                    issues.append("Root login permitted")
                if 'PasswordAuthentication yes' in content:
                    issues.append("Password authentication enabled")
        except Exception as e:
            return {"ok": False, "error": str(e), "config_path": config_path}

        findings = {"issues": issues}
        return {
            "ok": True,
            "config_path": config_path,
            "findings": findings,
            "note": "Weak config detection completed."
        }