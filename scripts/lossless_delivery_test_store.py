#!/usr/bin/env python3
"""Driver-owned durable host store for §21 native delivery operations.

The production adapter uses this portable JSON command boundary for the test.
The driver and test transport inspect the SQLite file without calling the adapter.
No production database schema or implementation language is prescribed.
"""
from __future__ import annotations

import hashlib
import os
import signal
import sqlite3
import sys
import uuid
from pathlib import Path

from validate_conformance import analyze_json_artifact_source, canonical_json_bytes


def document(raw: bytes) -> dict:
    parsed = analyze_json_artifact_source(raw)
    if parsed.error or type(parsed.document) is not dict:
        raise ValueError('host store request is not strict JSON')
    return parsed.document


def digest(raw: bytes) -> str:
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def handle(request: dict) -> dict:
    path = Path(request['database_path'])
    with sqlite3.connect(path, timeout=10) as connection:
        connection.execute('PRAGMA synchronous=FULL')
        connection.executescript('''
            CREATE TABLE IF NOT EXISTS host_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                run_id TEXT NOT NULL, state_json BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS native_transactions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL, operation_id TEXT NOT NULL UNIQUE,
                native_transaction_id TEXT NOT NULL UNIQUE,
                before_digest TEXT NOT NULL, after_digest TEXT NOT NULL,
                proof_id TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS crash_cuts (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL, operation_id TEXT NOT NULL UNIQUE,
                phase TEXT NOT NULL);
        ''')
        kind = request['kind']
        if kind == 'seed':
            state = canonical_json_bytes(request['before'])
            connection.execute('INSERT INTO host_state(singleton,run_id,state_json) VALUES(1,?,?)',
                               (request['run_id'], state))
            return {'seed_digest': digest(state)}
        row = connection.execute('SELECT run_id,state_json FROM host_state WHERE singleton=1').fetchone()
        if row is None or row[0] != request['run_id']:
            raise ValueError('host store run identity differs')
        if kind == 'crash_before_commit':
            connection.execute('INSERT INTO crash_cuts(run_id,operation_id,phase) VALUES(?,?,?)',
                               (row[0], request['operation_id'], 'before_commit'))
            connection.commit()
            os.kill(os.getppid(), signal.SIGKILL)
            return {'cut': 'before_commit'}
        if kind == 'commit':
            before_digest = digest(row[1])
            if request['expected_before_digest'] != before_digest:
                raise ValueError('host store compare-and-swap before digest differs')
            after = canonical_json_bytes(request['after'])
            transaction_id = str(uuid.uuid4())
            after_digest = digest(after)
            proof_id = digest(canonical_json_bytes([
                'determa-delivery-native-commit-1', row[0], request['operation_id'],
                transaction_id, before_digest, after_digest]))
            connection.execute('UPDATE host_state SET state_json=? WHERE singleton=1', (after,))
            connection.execute('INSERT INTO native_transactions('
                               'run_id,operation_id,native_transaction_id,before_digest,after_digest,proof_id) '
                               'VALUES(?,?,?,?,?,?)',
                               (row[0], request['operation_id'], transaction_id,
                                before_digest, after_digest, proof_id))
            if request.get('crash_after_commit') is True:
                connection.execute('INSERT INTO crash_cuts(run_id,operation_id,phase) VALUES(?,?,?)',
                                   (row[0], request['operation_id'], 'after_commit'))
                connection.commit()
                os.kill(os.getppid(), signal.SIGKILL)
            return {'native_transaction_id': transaction_id, 'proof_id': proof_id,
                    'before_digest': before_digest, 'after_digest': after_digest}
        if kind == 'snapshot':
            transactions = [{'operation_id': operation_id,
                             'native_transaction_id': transaction_id,
                             'before_digest': before_digest,
                             'after_digest': after_digest, 'proof_id': proof_id}
                            for operation_id, transaction_id, before_digest,
                                after_digest, proof_id in connection.execute(
                                'SELECT operation_id,native_transaction_id,before_digest,after_digest,proof_id '
                                'FROM native_transactions ORDER BY sequence')]
            crash_cuts = [{'operation_id': operation_id, 'phase': phase}
                          for operation_id, phase in connection.execute(
                              'SELECT operation_id,phase FROM crash_cuts ORDER BY sequence')]
            return {'after': document(row[1]), 'transactions': transactions,
                    'crash_cuts': crash_cuts}
        raise ValueError('unknown host store operation')


if __name__ == '__main__':
    try:
        sys.stdout.buffer.write(canonical_json_bytes(handle(document(sys.stdin.buffer.read()))))
    except (ValueError, KeyError, sqlite3.Error) as error:
        sys.stderr.write(str(error) + '\n')
        sys.exit(1)
