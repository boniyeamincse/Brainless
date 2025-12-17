import json

class Module:
    @staticmethod
    def meta():
        return {
            "name": "reporting/export_html",
            "description": "Exports findings to an HTML file.",
            "author": "Brainless Team",
            "tags": ["reporting", "html", "export", "safe"]
        }

    @staticmethod
    def default_options():
        return {
            "DATA": "{}",
            "OUTPUT_FILE": "report.html"
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
            html = f"<html><body><h1>Report</h1><pre>{json.dumps(data, indent=2)}</pre></body></html>"
            with open(output_file, 'w') as f:
                f.write(html)
        except Exception as e:
            return {"ok": False, "error": str(e), "output_file": output_file}

        return {
            "ok": True,
            "output_file": output_file,
            "note": "Findings exported to HTML."
        }