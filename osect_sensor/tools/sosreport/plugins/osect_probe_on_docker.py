import os

from sos.report.plugins import IndependentPlugin, Plugin


class osect_probe_on_docker_logs(Plugin, IndependentPlugin):
    def setup(self):
        sos_logs_path = os.environ.get("SOS_LOGS_PATH", None)
        if sos_logs_path:
            self.add_copy_spec(
                [
                    "/var/log",
                    "%s/logs/ottools" % (sos_logs_path),
                ]
            )
