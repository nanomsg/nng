#!/usr/bin/env python3
# Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt). A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

"""Run long-lived DTLS peers through seeded UDP faults on macOS or Linux."""

import argparse
import collections
import concurrent.futures
import heapq
import hashlib
import json
import os
from pathlib import Path
import random
import re
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback


class Failure(RuntimeError):
    pass


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def resource_sample(pids):
    """Sample current RSS, descriptor and thread counts, without third-party modules."""
    if sys.platform.startswith('linux'):
        result = {}
        for pid in pids:
            try:
                fields = dict(line.split(':', 1) for line in
                              Path(f'/proc/{pid}/status').read_text().splitlines()
                              if ':' in line)
                result[pid] = {'rss_kib': int(fields['VmRSS'].split()[0]),
                               'fds': len(os.listdir(f'/proc/{pid}/fd')),
                               'threads': int(fields['Threads'])}
            except (FileNotFoundError, ProcessLookupError):
                continue
        return result
    pid_list = ','.join(map(str, pids))
    rows = subprocess.run(['ps', '-o', 'pid=,rss=', '-p', pid_list],
                          capture_output=True, text=True, timeout=10, check=True)
    result = {int(p): {'rss_kib': int(r)} for p, r in
              (line.split() for line in rows.stdout.splitlines())}
    threads = subprocess.run(['ps', '-M', '-p', pid_list],
                             capture_output=True, text=True, timeout=10, check=True)
    counts = collections.Counter()
    for line in threads.stdout.splitlines():
        fields = line.split()
        if fields and fields[0].isdigit():
            counts[int(fields[0])] += 1
        elif len(fields) > 1 and fields[1].isdigit():
            counts[int(fields[1])] += 1
    files = subprocess.run(['lsof', '-nP', '-p', pid_list, '-Fpf'],
                           capture_output=True, text=True, timeout=15, check=True)
    fds = collections.Counter()
    pid = None
    for line in files.stdout.splitlines():
        if line.startswith('p'):
            pid = int(line[1:])
        elif pid is not None and line.startswith('f') and line[1:].isdigit():
            fds[pid] += 1
    for pid, value in result.items():
        value.update(fds=fds[pid], threads=counts[pid])
    return result


class Peer:
    def __init__(self, runner, name, command, role):
        self.runner, self.name, self.role = runner, name, role
        self.log = (runner.out / f'{name}.jsonl').open('wb')
        self.error_log = (runner.out / f'{name}.stderr').open('wb')
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                        stderr=self.error_log, stdin=subprocess.DEVNULL)
        os.set_blocking(self.process.stdout.fileno(), False)
        runner.selector.register(self.process.stdout, selectors.EVENT_READ, self)
        self.buffer = b''
        self.latest = {}
        self.ready = None
        self.last_event = time.monotonic()
        self.progress = {}
        self.baseline = collections.Counter()
        self.resources = collections.deque()
        self.current_resources = {}
        runner.peers.append(self)
        self.command = command

    def readable(self):
        data = os.read(self.process.stdout.fileno(), 65536)
        if not data:
            self.runner.selector.unregister(self.process.stdout)
            return
        self.log.write(data)
        self.log.flush()
        self.buffer += data
        if len(self.buffer) > 1024 * 1024:
            raise Failure(f'{self.name}: malformed/unbounded peer output')
        while b'\n' in self.buffer:
            line, self.buffer = self.buffer.split(b'\n', 1)
            event = json.loads(line)
            self.last_event = time.monotonic()
            if event.get('event') == 'ready':
                self.ready = event
            elif event.get('event') == 'sample':
                self.latest = event
                if self.role == 'client':
                    for index, worker in enumerate(event['workers']):
                        old, stamp = self.progress.get(index, (0, self.last_event))
                        if worker['ok'] > old:
                            stamp = self.last_event
                        self.progress[index] = (worker['ok'], stamp)
                elif event['pending'] > 16:
                    raise Failure(f'{self.name}: pending admission exceeds configured limit')

    def check(self, now, watchdog):
        if self.process.poll() is not None:
            raise Failure(f'{self.name}: exited early ({self.process.returncode}); see stderr')
        if now - self.last_event > watchdog:
            raise Failure(f'{self.name}: no heartbeat for {watchdog}s')
        for index, (_, stamp) in self.progress.items():
            if now - stamp > watchdog:
                raise Failure(f'{self.name}: worker {index} stopped completing requests')

    def sample(self, now, elapsed, value):
        self.current_resources = value
        self.resources.append((now, value))
        window = self.runner.args.resource_window
        while self.resources and now - self.resources[0][0] > window:
            self.resources.popleft()
        if elapsed <= self.runner.args.warmup or not self.baseline:
            for key, number in value.items():
                self.baseline[key] = max(self.baseline[key], number)
        if value['rss_kib'] > self.runner.args.max_rss_mib * 1024:
            raise Failure(f'{self.name}: RSS exceeds absolute limit')
        if elapsed <= self.runner.args.warmup + window or len(self.resources) < 2:
            return
        limits = {'rss_kib': self.runner.args.rss_growth_mib * 1024,
                  'fds': self.runner.args.fd_growth, 'threads': self.runner.args.thread_growth}
        for key, limit in limits.items():
            floor = min(sample[key] for _, sample in self.resources)
            if floor > self.baseline[key] + limit:
                raise Failure(f'{self.name}: sustained {key} growth: baseline '
                              f'{self.baseline[key]}, recent minimum {floor}, allowance {limit}')

    def summary(self):
        return {'pid': self.process.pid, 'role': self.role, 'sample': self.latest,
                'resources': self.current_resources, 'warmup_peak': dict(self.baseline)}


class Route:
    def __init__(self, case, client):
        self.case, self.client = case, client
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.last = time.monotonic()
        case.runner.selector.register(self.sock, selectors.EVENT_READ, self)

    def readable(self):
        data, addr = self.sock.recvfrom(65536)
        if addr != self.case.server_address:
            raise Failure(f'{self.case.name}: unexpected upstream source')
        self.last = time.monotonic()
        self.case.forward(self.case.front, self.client, data)

    def close(self):
        self.case.runner.selector.unregister(self.sock)
        self.sock.close()


class Case:
    def __init__(self, runner, name, server, client, version):
        self.runner, self.name, self.version = runner, name, version
        self.routes = {}
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(('127.0.0.1', 0))
        self.noise = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.noise.bind(('127.0.0.1', 0))
        runner.selector.register(self.front, selectors.EVENT_READ, self)
        self.server = Peer(runner, name + '-server', [str(server), 'server', version], 'server')
        self.client_binary = client
        self.client = None
        self.server_address = None
        self.hello = None
        self.rogues = []
        self.next_storm = runner.started + min(30, runner.args.storm_period)
        self.next_noise = 0
        self.counts = collections.Counter()
        self.trace = collections.deque(maxlen=256)

    def start_client(self):
        if self.client is None and self.server.ready:
            self.server_address = ('127.0.0.1', int(self.server.ready['url'].rsplit(':', 1)[1]))
            url = f'dtls4://127.0.0.1:{self.front.getsockname()[1]}'
            a = self.runner.args
            self.client = Peer(self.runner, self.name + '-client',
                               [str(self.client_binary), 'client', self.version, url,
                                str(a.persistent), str(a.churn), str(a.pace_ms)], 'client')

    def readable(self):
        data, addr = self.front.recvfrom(65536)
        if self.server_address is None:
            return
        route = self.routes.get(addr)
        if route is None:
            if len(self.routes) >= 128:
                raise Failure(f'{self.name}: proxy route limit exhausted')
            route = self.routes[addr] = Route(self, addr)
        route.last = time.monotonic()
        if (self.hello is None and len(data) >= 25 and data[0] == 22
                and data[3:5] == b'\0\0' and data[13] == 1):
            self.hello = data
        self.forward(route.sock, self.server_address, data)

    def forward(self, sock, address, data):
        self.counts['packets'] += 1
        r, a = self.runner, self.runner.args
        elapsed = time.monotonic() - r.started
        event = {'elapsed': round(elapsed, 3), 'bytes': len(data),
                 'direction': 'reply' if sock is self.front else 'request',
                 'prefix': data[:25].hex(), 'action': 'forward'}
        self.trace.append(event)
        faults = elapsed < a.duration - a.recovery
        if faults and elapsed >= a.fault_period and elapsed % a.fault_period < a.blackout:
            event['action'] = 'blackout'
            self.counts['blackout_dropped'] += 1
            return
        if faults and r.random.random() < a.loss:
            event['action'] = 'loss'
            self.counts['dropped'] += 1
            return
        copies = 2 if faults and r.random.random() < a.duplicate else 1
        self.counts['duplicates'] += copies - 1
        for _ in range(copies):
            delay = r.random.uniform(0.005, a.max_delay_ms / 1000) if (
                faults and r.random.random() < a.reorder) else 0
            if delay:
                self.counts['delayed'] += 1
            r.serial += 1
            if len(r.delayed) >= 4096:
                raise Failure('proxy delayed-packet queue exhausted')
            heapq.heappush(r.delayed, (time.monotonic() + delay, r.serial, sock, address, data))

    def tick(self, now):
        self.start_client()
        for addr, route in list(self.routes.items()):
            if now - route.last > 15:
                route.close()
                del self.routes[addr]
        for sock, expiry in list(self.rogues):
            if now >= expiry:
                sock.close()
                self.rogues.remove((sock, expiry))
        if now - self.runner.started >= self.runner.args.duration - self.runner.args.recovery:
            return
        if self.server_address and now >= self.next_noise:
            self.noise.sendto(b'\x17' + self.runner.random.randbytes(63), self.server_address)
            self.counts['garbage_sent'] += 1
            self.next_noise = now + 0.25
        if self.hello and now >= self.next_storm:
            # Each new source starts a real TLS handshake but never echoes its
            # cookie. More sources than pending slots exercise rejection/recovery.
            for _ in range(32):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('127.0.0.1', 0))
                sock.sendto(self.hello, self.server_address)
                self.rogues.append((sock, now + 6))
            self.counts['storms'] += 1
            self.next_storm = now + self.runner.args.storm_period

    def summary(self):
        return {'version': self.version, 'routes': len(self.routes),
                'rogues': len(self.rogues), 'network': dict(self.counts)}

    def close(self):
        for route in self.routes.values():
            route.close()
        for sock, _ in self.rogues:
            sock.close()
        self.runner.selector.unregister(self.front)
        self.front.close()
        self.noise.close()


class Runner:
    def __init__(self, args):
        self.args = args
        self.out = args.output.resolve()
        self.out.mkdir(parents=True, exist_ok=False)
        (self.out / 'runner.pid').write_text(str(os.getpid()) + '\n')
        self.selector = selectors.DefaultSelector()
        self.random = random.Random(args.seed)
        self.delayed, self.peers, self.cases = [], [], []
        self.serial = 0
        self.started = time.monotonic()
        self.wall_start = time.time()
        self.stop = False
        self.failure = None
        self.capabilities = {}
        self.current_resources = {}
        self.resource_peak = collections.Counter()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.future = None
        self.awake = None
        self.samples = (self.out / 'samples.jsonl').open('a')
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self.interrupt)

    def interrupt(self, _sig, _frame):
        self.stop = True

    def preflight(self):
        if sys.platform not in ('darwin', 'linux'):
            raise Failure('resource monitoring currently supports macOS and Linux')
        own = resource_sample([os.getpid()])[os.getpid()]
        if own['fds'] < 3 or own['threads'] < 1 or own['rss_kib'] <= 0:
            raise Failure('resource sampler did not return usable process metrics')
        self.current_resources = own
        self.resource_peak.update(own)
        if self.args.keep_awake:
            if sys.platform != 'darwin' or not shutil.which('caffeinate'):
                raise Failure('--keep-awake requires macOS caffeinate')
            self.awake = subprocess.Popen(['caffeinate', '-i', '-w', str(os.getpid())],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
        binaries = {}
        for entry in self.args.peer:
            name, separator, path = entry.partition('=')
            if not separator or not re.fullmatch(r'[A-Za-z0-9_-]+', name) or name in binaries:
                raise Failure('--peer requires unique NAME=EXECUTABLE entries')
            binaries[name] = Path(path).resolve(strict=True)
        if not binaries:
            raise Failure('at least one --peer NAME=EXECUTABLE is required')
        builds = {}
        for name, binary in binaries.items():
            builds[name] = {'path': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'probes': {}}
            self.capabilities[name] = []
            for version in ('12', '13'):
                result = subprocess.run([str(binary), 'probe', version],
                                        capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    builds[name]['probes'][version] = json.loads(result.stdout)
                    self.capabilities[name].append(version)
                elif result.returncode != 77:
                    raise Failure(f'{name} DTLS {version} probe failed: {result.stderr}')
            if not self.capabilities[name]:
                raise Failure(f'{name}: neither DTLS version could be enabled')
        for server, binary in binaries.items():
            for client, client_binary in binaries.items():
                if self.args.self_only and server != client:
                    continue
                for version in (self.args.version or ('12', '13')):
                    if version in self.capabilities[server] and version in self.capabilities[client]:
                        name = f'{server}-from-{client}-{version}'
                        self.cases.append(Case(self, name, binary, client_binary, version))
        if not self.cases:
            raise Failure('no supported DTLS scenarios')
        source = Path(__file__).resolve().parents[4]
        revision = None
        if shutil.which('git'):
            revision = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'],
                                      capture_output=True, text=True).stdout.strip() or None
        for relative in ('src/sp/transport/dtls/dtls_soak.py', 'src/sp/transport/dtls/dtls_soak_peer.c',
                         'src/sp/transport/dtls/CMakeLists.txt', 'src/sp/transport/dtls/dtls.c',
                         'src/supplemental/tls/tls_common.c', 'docs/DTLS_SOAK.md'):
            original = source / relative
            if original.exists():
                target = self.out / 'source' / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(original, target)
        atomic_json(self.out / 'manifest.json', {
            'arguments': vars(self.args) | {'output': str(self.out)},
            'capabilities': self.capabilities, 'python': sys.version,
            'platform': sys.platform, 'started_at': self.wall_start,
            'binaries': builds, 'revision': revision,
            'sanitizers': {name: os.environ[name] for name in
                           ('ASAN_OPTIONS', 'LSAN_OPTIONS', 'UBSAN_OPTIONS') if name in os.environ},
        })

    def snapshot(self, state):
        elapsed = time.monotonic() - self.started
        return {'state': state, 'pid': os.getpid(), 'started_at': self.wall_start,
                'expected_end_at': self.wall_start + self.args.duration,
                'elapsed_seconds': round(elapsed, 1), 'failure': self.failure,
                'runner_resources': self.current_resources,
                'runner_peak': dict(self.resource_peak),
                'phase': ('recovery' if elapsed >= self.args.duration - self.args.recovery else
                          'warmup' if elapsed <= self.args.warmup else 'soak'),
                'peers': {p.name: p.summary() for p in self.peers},
                'cases': {c.name: c.summary() for c in self.cases}}

    def write_progress(self, snapshot):
        total = sum(w['ok'] for p in self.peers for w in p.latest.get('workers', []))
        rss = sum(p.current_resources.get('rss_kib', 0) for p in self.peers) / 1024
        lines = [f"# DTLS soak: {snapshot['state']}", '',
                 f"Elapsed: {snapshot['elapsed_seconds']:.0f} / {self.args.duration:.0f} seconds. "
                 f"Phase: {snapshot['phase']}. Seed: {self.args.seed}.", '',
                 f"Verified replies: **{total:,}**. Peers: {len(self.peers)}. "
                 f"Combined peer RSS: {rss:.1f} MiB.", '',
                 f"Failure: {self.failure or 'none observed in this run'}.", '',
                 '| Scenario | Verified replies | Timeouts | Socket opens | Pending |',
                 '| --- | ---: | ---: | ---: | ---: |']
        for case in self.cases:
            workers = case.client.latest.get('workers', []) if case.client else []
            values = [sum(w[key] for w in workers) for key in ('ok', 'timeouts', 'cycles')]
            lines.append(f"| {case.name} | {values[0]:,} | {values[1]:,} | "
                         f"{values[2]:,} | {case.server.latest.get('pending', 0)} |")
        lines += ['', 'See status.json and samples.jsonl for resources and network counters.', '']
        temporary = self.out / 'progress.tmp'
        temporary.write_text('\n'.join(lines))
        temporary.replace(self.out / 'progress.md')

    def run(self):
        state = 'failed'
        try:
            self.preflight()
            next_status, next_resource = 0, 0
            while not self.stop and time.monotonic() - self.started < self.args.duration:
                for key, _ in self.selector.select(timeout=0.02):
                    key.data.readable()
                now = time.monotonic()
                while self.delayed and self.delayed[0][0] <= now:
                    _, _, sock, addr, data = heapq.heappop(self.delayed)
                    if sock.fileno() != -1:
                        sock.sendto(data, addr)
                for case in self.cases:
                    case.tick(now)
                for peer in self.peers:
                    peer.check(now, self.args.watchdog)
                if self.future is not None and self.future.done():
                    result = self.future.result()
                    if os.getpid() in result:
                        self.current_resources = result[os.getpid()]
                        for key, value in self.current_resources.items():
                            self.resource_peak[key] = max(self.resource_peak[key], value)
                    for peer in self.peers:
                        if peer.process.pid in result:
                            value = result[peer.process.pid]
                            if value['fds'] < 3 or value['threads'] < 1:
                                raise Failure(f'{peer.name}: unusable resource sample')
                            peer.sample(now, now - self.started, value)
                        elif peer.process.pid in self.sample_pids:
                            raise Failure(f'{peer.name}: process disappeared during resource sampling')
                    self.future = None
                if now >= next_resource and self.future is None:
                    self.sample_pids = [os.getpid()] + [p.process.pid for p in self.peers]
                    self.future = self.executor.submit(resource_sample, self.sample_pids)
                    next_resource = now + self.args.sample_interval
                if now >= next_status:
                    snapshot = self.snapshot('running')
                    atomic_json(self.out / 'status.json', snapshot)
                    self.write_progress(snapshot)
                    self.samples.write(json.dumps(snapshot) + '\n')
                    self.samples.flush()
                    total = sum(w['ok'] for p in self.peers for w in p.latest.get('workers', []))
                    print(f"{int(now - self.started)}s: {len(self.cases)} scenarios, {total} verified replies", flush=True)
                    next_status = now + self.args.sample_interval
            if self.stop:
                state = 'stopped'
            else:
                for case in self.cases:
                    if case.client is None or not case.client.latest.get('workers'):
                        raise Failure(f'{case.name}: client never reported progress')
                    for index, worker in enumerate(case.client.latest['workers']):
                        if worker['ok'] == 0:
                            raise Failure(f'{case.name}: worker {index} never completed a request')
                        if time.monotonic() - case.client.progress[index][1] > min(10, self.args.recovery / 2):
                            raise Failure(f'{case.name}: worker {index} did not recover during the quiet phase')
                        if index >= self.args.persistent and worker['cycles'] < 2:
                            raise Failure(f'{case.name}: churn worker never reconnected')
                    if not case.counts['storms'] or not case.server.latest.get('rejected'):
                        raise Failure(f'{case.name}: admission pressure was not exercised')
                    if not case.counts['blackout_dropped']:
                        raise Failure(f'{case.name}: blackout recovery was not exercised')
                state = 'passed'
        except Exception as error:
            self.failure = str(error)
            details = traceback.format_exc()
            # stderr is already open. Keep the original cause even if host
            # descriptor exhaustion prevents creating diagnostic files.
            print(f'FAIL: {error}\n{details}', file=sys.stderr, flush=True)
            try:
                (self.out / 'failure.txt').write_text(details)
                if sys.platform == 'darwin' and shutil.which('sample'):
                    for peer in self.peers:
                        if peer.name in self.failure and peer.process.poll() is None:
                            with (self.out / (peer.name + '.sample.log')).open('w') as log:
                                try:
                                    subprocess.run(['sample', str(peer.process.pid), '1', '1', '-file',
                                                    str(self.out / (peer.name + '.sample.txt'))],
                                                   stdout=log, stderr=subprocess.STDOUT, timeout=10)
                                except subprocess.TimeoutExpired:
                                    pass
            except OSError as diagnostic_error:
                print(f'Could not save failure diagnostics: {diagnostic_error}',
                      file=sys.stderr, flush=True)
        finally:
            cleanup = self.cleanup()
            if cleanup and state == 'passed':
                state, self.failure = 'failed', cleanup
            snapshot = self.snapshot(state)
            if self.failure:
                atomic_json(self.out / 'network-tail.json', {c.name: list(c.trace) for c in self.cases})
            atomic_json(self.out / 'status.json', snapshot)
            self.write_progress(snapshot)
            (self.out / 'summary.md').write_text(
                f"# DTLS soak: {state}\n\nDuration: {snapshot['elapsed_seconds']} seconds.\n\n"
                f"Scenarios: {len(self.cases)}. Seed: {self.args.seed}.\n\n"
                f"Failure: {self.failure or 'none'}.\n\n"
                'See status.json for final counters and resources, samples.jsonl for trends,\n'
                'and each peer stderr/JSONL log for diagnostics.\n')
            self.samples.close()
            print(f'{state}: {self.out}', flush=True)
        return 0 if state == 'passed' else 130 if state == 'stopped' else 1

    def cleanup(self):
        failure = None
        for peer in self.peers:
            if peer.process.poll() is None:
                peer.process.terminate()
        deadline = time.monotonic() + 10
        while any(p.process.poll() is None for p in self.peers) and time.monotonic() < deadline:
            for key, _ in self.selector.select(timeout=0.1):
                try:
                    key.data.readable()
                except (OSError, ValueError):
                    pass
        for peer in self.peers:
            if peer.process.poll() is None:
                peer.process.kill()
                failure = f'{peer.name}: did not shut down within 10 seconds'
            if peer.process.wait() != 0:
                failure = f'{peer.name}: nonzero exit on shutdown ({peer.process.returncode})'
            peer.process.stdout.close()
            peer.log.close()
            peer.error_log.close()
        for case in self.cases:
            case.close()
        self.selector.close()
        self.executor.shutdown(wait=True)
        if self.awake is not None:
            self.awake.terminate()
            self.awake.wait()
        return failure


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer', action='append', required=True, help='NAME=path/to/dtls_soak_peer (repeatable)')
    parser.add_argument('--output', type=Path, required=True, help='new directory for status and logs')
    parser.add_argument('--duration', type=float, default=14400, help='seconds (default: 4 hours)')
    parser.add_argument('--seed', type=int, default=2391)
    parser.add_argument('--version', action='append', choices=('12', '13'), help='restrict protocol versions (repeatable)')
    parser.add_argument('--self-only', action='store_true', help='omit cross-engine combinations')
    parser.add_argument('--persistent', type=int, default=2)
    parser.add_argument('--churn', type=int, default=1)
    parser.add_argument('--pace-ms', type=int, default=100)
    parser.add_argument('--loss', type=float, default=0.02)
    parser.add_argument('--duplicate', type=float, default=0.01)
    parser.add_argument('--reorder', type=float, default=0.10)
    parser.add_argument('--max-delay-ms', type=float, default=50)
    parser.add_argument('--fault-period', type=float, default=300)
    parser.add_argument('--blackout', type=float, default=30)
    parser.add_argument('--storm-period', type=float, default=120)
    parser.add_argument('--recovery', type=float, default=30, help='final seconds without injected faults')
    parser.add_argument('--watchdog', type=float, default=90)
    parser.add_argument('--warmup', type=float, default=300)
    parser.add_argument('--resource-window', type=float, default=60)
    parser.add_argument('--sample-interval', type=float, default=15)
    parser.add_argument('--max-rss-mib', type=int, default=512)
    parser.add_argument('--rss-growth-mib', type=int, default=32)
    parser.add_argument('--fd-growth', type=int, default=16)
    parser.add_argument('--thread-growth', type=int, default=4)
    parser.add_argument('--keep-awake', action='store_true', help='prevent macOS idle sleep during the run')
    args = parser.parse_args()
    if not (1 <= args.persistent <= 8 and 1 <= args.churn <= 8 and 1 <= args.pace_ms <= 1000):
        parser.error('persistent/churn must be 1..8 and pace-ms 1..1000')
    if not all(0 <= p <= 1 for p in (args.loss, args.duplicate, args.reorder)):
        parser.error('fault probabilities must be in 0..1')
    if not (args.duration > args.warmup + args.resource_window and
            0 < args.recovery < args.duration and
            0 < args.blackout < args.fault_period < args.duration - args.recovery and
            0 < args.storm_period < args.duration - args.recovery and
            args.sample_interval > 0 and args.watchdog > 10 and args.max_delay_ms >= 5):
        parser.error('duration must allow warmup, a full fault cycle, resource observation and recovery')
    return args


if __name__ == '__main__':
    sys.exit(Runner(arguments()).run())
