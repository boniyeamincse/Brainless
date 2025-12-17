import json

class Module:
    @staticmethod
    def meta():
        return {
            "name": "reporting/export_json",
            "description": "Exports findings to a JSON file.",
            "author": "Brainless Team",
            "tags": ["reporting", "json", "export", "safe"]
        }

    @staticmethod
    def default_options():
        return {
            "DATA": "{}",
            "OUTPUT_FILE": "report.json"
        }

    @staticmethod
    def validate(opts):
        if not opts.get("DATA"):
            return False, "DATA is required"
        if not opts.get("OUTPUT_FILE"):
            return False, "OUTPUT_FILE is required"
        return True, "OK"

    def run(self, opts, context=None):
        ok, msg = self.validate(opts)
        if not ok:
            return {"ok": False, "error": msg}

        data_str = opts["DATA"]
        output_file = opts["OUTPUT_FILE"]

        try:
            data = json.loads(data_str)
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            return {"ok": False, "error": str(e), "output_file": output_file}

        return {
            "ok": True,
            "output_file": output_file,
            "note": "Findings exported to JSON."
        }