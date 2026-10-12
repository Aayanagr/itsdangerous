"""Run the signing service: ``DEMO_SECRET=... python -m demo_api``."""

from __future__ import annotations

import logging
import os
import sys

from demo_api.app import ConfigError
from demo_api.app import make_server
from demo_api.app import read_secret

PORT = 8081


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        secret = read_secret(os.environ)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    server = make_server(secret, host="0.0.0.0", port=PORT)
    logging.getLogger("demo_api").info("listening on port %d", PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
