#!/usr/bin/env python3
# Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#
"""Exchange authenticated DTLS messages between two NNG engine builds."""

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor


def exchange(server_bin, client_bin, version):
    with ThreadPoolExecutor(max_workers=1) as pool:
        with subprocess.Popen(
            [server_bin, version], stdout=subprocess.PIPE, text=True
        ) as server:
            try:
                url = pool.submit(server.stdout.readline).result(timeout=15).strip()
                if not url:
                    raise RuntimeError("server exited without publishing a listener URL")
                subprocess.run([client_bin, version, url], timeout=15, check=True)
                if server.wait(timeout=15) != 0:
                    raise RuntimeError("server failed to receive and echo the message")
                print(f"DTLS 1.{version[-1]}: {client_bin} -> {server_bin}: passed")
            finally:
                if server.poll() is None:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    first, second = sys.argv[1:]
    for protocol in ("12", "13"):
        exchange(first, second, protocol)
        exchange(second, first, protocol)
