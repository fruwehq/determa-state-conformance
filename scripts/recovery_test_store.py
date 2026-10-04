#!/usr/bin/env python3
"""Driver-owned native persistence boundary for recovery conformance probes.

The adapter receives this public command and a fresh database path. The runner
reads the database through this provider after each child process exits. The
SQLite layout is a test provider detail, not a production storage requirement.
"""
from __future__ import annotations

import hashlib
import sqlite3
import sys
import uuid
from pathlib import Path

from validate_conformance import analyze_json_artifact_source, canonical_json_bytes


def strict(raw: bytes) -> dict:
    parsed = analyze_json_artifact_source(raw)
    if parsed.error or type(parsed.document) is not dict:
        raise ValueError('strict object required')
    return parsed.document


def digest(raw: bytes) -> str:
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def handle(request: dict) -> dict:
    if set(request) not in ({'kind', 'database_path', 'run_id', 'initial'},
                            {'kind', 'database_path', 'run_id'},
                            {'kind', 'database_path', 'run_id', 'operation_id', 'phase',
                             'request_digest', 'bridge_identity'},
                            {'kind', 'database_path', 'run_id', 'operation_id',
                             'response_digest', 'outcome'},
                            {'kind', 'database_path', 'run_id', 'operation_id', 'phase',
                             'request_digest', 'expected_before_digest', 'after', 'response_digest'}):
        raise ValueError('closed recovery store command required')
    path = Path(request['database_path'])
    with sqlite3.connect(path, timeout=10) as connection:
        connection.execute('PRAGMA synchronous=FULL')
        connection.executescript('''
            CREATE TABLE IF NOT EXISTS native_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                run_id TEXT NOT NULL, state_json BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS native_transactions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL, operation_id TEXT NOT NULL UNIQUE,
                phase TEXT NOT NULL, request_digest TEXT NOT NULL,
                response_digest TEXT NOT NULL, before_digest TEXT NOT NULL,
                after_digest TEXT NOT NULL, native_transaction_id TEXT NOT NULL UNIQUE,
                proof_id TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS native_invocations (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL, operation_id TEXT NOT NULL UNIQUE,
                phase TEXT NOT NULL, request_digest TEXT NOT NULL,
                bridge_identity TEXT NOT NULL, response_digest TEXT,
                outcome TEXT);
        ''')
        kind = request['kind']
        if kind == 'init':
            initial = canonical_json_bytes(request['initial'])
            connection.execute('INSERT INTO native_state VALUES(1,?,?)',
                               (request['run_id'], initial))
            return {'initial_digest': digest(initial)}
        row = connection.execute('SELECT run_id,state_json FROM native_state WHERE singleton=1').fetchone()
        if row is None or row[0] != request['run_id']:
            raise ValueError('recovery store run identity differs')
        if kind == 'snapshot':
            transactions = [dict(zip(('operation_id', 'phase', 'request_digest',
                                      'response_digest', 'before_digest', 'after_digest',
                                      'native_transaction_id', 'proof_id'), entry))
                            for entry in connection.execute(
                                'SELECT operation_id,phase,request_digest,response_digest,'
                                'before_digest,after_digest,native_transaction_id,proof_id '
                                'FROM native_transactions ORDER BY sequence')]
            invocations = [dict(zip(('operation_id', 'phase', 'request_digest',
                                     'bridge_identity', 'response_digest', 'outcome'), entry))
                           for entry in connection.execute(
                               'SELECT operation_id,phase,request_digest,bridge_identity,'
                               'response_digest,outcome FROM native_invocations ORDER BY sequence')]
            return {'state': strict(row[1]), 'transactions': transactions,
                    'invocations': invocations}
        if kind == 'invocation_start':
            connection.execute('INSERT INTO native_invocations('
                               'run_id,operation_id,phase,request_digest,bridge_identity) '
                               'VALUES(?,?,?,?,?)',
                               (row[0], request['operation_id'], request['phase'],
                                request['request_digest'], request['bridge_identity']))
            return {'started': True}
        if kind == 'invocation_return':
            if request['outcome'] not in ('returned', 'failed'):
                raise ValueError('closed native invocation outcome required')
            updated = connection.execute('UPDATE native_invocations SET '
                'response_digest=?,outcome=? WHERE run_id=? AND operation_id=? '
                'AND response_digest IS NULL',
                (request['response_digest'], request['outcome'], row[0],
                 request['operation_id'])).rowcount
            if updated != 1:
                raise ValueError('missing or repeated native invocation return')
            transaction = connection.execute(
                'SELECT response_digest FROM native_transactions WHERE operation_id=?',
                (request['operation_id'],)).fetchone()
            if transaction is not None and transaction[0] != request['response_digest']:
                raise ValueError('native return differs from committed response')
            return {'returned': True}
        if kind != 'commit' or request['phase'] not in (
                'archive_stage', 'recovery', 'scope_terminate'):
            raise ValueError('unknown recovery store operation')
        invocation = connection.execute(
            'SELECT phase,request_digest,response_digest FROM native_invocations '
            'WHERE run_id=? AND operation_id=?',
            (row[0], request['operation_id'])).fetchone()
        if invocation != (request['phase'], request['request_digest'], None):
            raise ValueError('native commit has no live public operation invocation')
        before_digest = digest(row[1])
        if request['expected_before_digest'] != before_digest:
            raise ValueError('recovery compare-and-swap before digest differs')
        after = canonical_json_bytes(request['after'])
        if after == row[1]:
            raise ValueError('unchanged operation cannot fabricate a native commit')
        transaction_id = str(uuid.uuid4())
        after_digest = digest(after)
        proof_id = digest(canonical_json_bytes([
            'determa-recovery-native-commit-1', row[0], request['operation_id'],
            request['phase'], request['request_digest'], request['response_digest'],
            transaction_id, before_digest, after_digest]))
        connection.execute('UPDATE native_state SET state_json=? WHERE singleton=1', (after,))
        connection.execute('INSERT INTO native_transactions('
                           'run_id,operation_id,phase,request_digest,response_digest,'
                           'before_digest,after_digest,native_transaction_id,proof_id) '
                           'VALUES(?,?,?,?,?,?,?,?,?)',
                           (row[0], request['operation_id'], request['phase'],
                            request['request_digest'], request['response_digest'],
                            before_digest, after_digest, transaction_id, proof_id))
        return {'native_transaction_id': transaction_id, 'proof_id': proof_id,
                'before_digest': before_digest, 'after_digest': after_digest}


if __name__ == '__main__':
    try:
        sys.stdout.buffer.write(canonical_json_bytes(handle(strict(sys.stdin.buffer.read()))))
    except (ValueError, KeyError, sqlite3.Error) as error:
        sys.stderr.write(str(error) + '\n')
        raise SystemExit(1)
