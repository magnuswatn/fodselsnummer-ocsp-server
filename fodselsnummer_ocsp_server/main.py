import multiprocessing

import gunicorn.app.base

from .config import OcspConfig
from .ocsp_server import app


def number_of_workers(config: OcspConfig):
    if config.workers != 0:
        return config.workers
    return (multiprocessing.cpu_count() * 2) + 1


class OcspServer(gunicorn.app.base.BaseApplication):
    def __init__(self, app, options):
        self.options = options
        self.application = app
        super(OcspServer, self).__init__()

    def load_config(self):
        config = dict(
            [
                (key, value)
                for key, value in self.options.items()
                if key in self.cfg.settings and value is not None  # type:ignore
            ]
        )
        for key, value in config.items():
            self.cfg.set(key.lower(), value)  # type:ignore

    def load(self):
        return self.application


def main():
    config = OcspConfig.create()
    options = {
        "bind": config.bind,
        "workers": number_of_workers(config),
    }
    OcspServer(app, options).run()
