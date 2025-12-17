import os
import stat

class Module:
    @staticmethod
    def meta():
        return {
            "name": "audit/local/file_permission_check",
            "description": "Checks file permissions for potential security issues.",
            "author": "Brainless Team",
            "tags": ["audit", "local", "file", "permissions", "safe"]
        }

    @staticmethod
    def default_options():
        return {
            "FILE_PATH": ""
        }

    @staticmethod
    def validate(opts):
        if not opts.get("FILE_PATH"):
            return False, "FILE_PATH is required"
        return True, "OK"

    def run(self, opts, context=None):
        ok, msg = self.validate(opts)
        if not ok:
            return {"ok": False, "error": msg}

        file_path = opts["FILE_PATH"]

        if not os.path.exists(file_path):
            return {"ok": False, "error": "File does not exist", "file_path": file_path}

        try:
            st = os.stat(file_path)
            permissions = stat.filemode(st.st_mode)
            owner = st.st_uid
            group = st.st_gid
            size = st.st_size
        except Exception as e:
            return {"ok": False, "error": str(e), "file_path": file_path}

        findings = {
            "permissions": permissions,
            "owner": owner,
            "group": group,
            "size": size
        }
        return {
            "ok": True,
            "file_path": file_path,
            "findings": findings,
            "note": "File permissions checked."
        }