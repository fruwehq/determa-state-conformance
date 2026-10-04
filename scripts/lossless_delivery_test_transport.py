#!/usr/bin/env python3
"""Inspectable durable transport used by the §21 production adapter driver.

The adapter invokes this program for source fetch/ack and destination transfer.
The driver reads the SQLite journal separately after every operation.
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from validate_conformance import analyze_json_artifact_source, canonical_json_bytes


def document(raw: bytes) -> dict:
    parsed = analyze_json_artifact_source(raw)
    if parsed.error or type(parsed.document) is not dict:
        raise ValueError('transport request is not strict JSON')
    return parsed.document


def handle(request: dict) -> dict:
    path = Path(request['database_path'])
    with sqlite3.connect(path) as connection:
        connection.execute('PRAGMA synchronous=FULL')
        connection.executescript('''
            CREATE TABLE IF NOT EXISTS sources (
                scope TEXT NOT NULL, delivery_id TEXT NOT NULL,
                source_json BLOB NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (scope, delivery_id));
            CREATE TABLE IF NOT EXISTS calls (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
                scope TEXT, delivery_id TEXT, effect_id TEXT, outcome TEXT,
                receipt_id TEXT, checkpoint_digest TEXT, transfer_digest TEXT,
                intent_json BLOB);
            CREATE TABLE IF NOT EXISTS acknowledgement_barrier (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                observer_command_json BLOB NOT NULL, run_id TEXT NOT NULL,
                operation_id TEXT NOT NULL, checkpoint_digest TEXT NOT NULL,
                transfer_digest TEXT NOT NULL);
        ''')
        kind = request['kind']
        if kind == 'configure_acknowledgement_barrier':
            command = request['observer_command']
            if type(command) is not list or not command or any(type(part) is not str for part in command):
                raise ValueError('observer command is incomplete')
            connection.execute('INSERT OR REPLACE INTO acknowledgement_barrier VALUES(1,?,?,?,?,?)',
                               (canonical_json_bytes(command), request['run_id'],
                                request['operation_id'], request['checkpoint_digest'],
                                request['transfer_digest']))
            return {'configured': True}
        if kind == 'seed':
            for source in request['sources']:
                connection.execute('INSERT INTO sources(scope,delivery_id,source_json,acknowledged) VALUES(?,?,?,?)',
                                   (source['source_scope'], source['source_delivery_id'],
                                    canonical_json_bytes(source['source']),
                                    int(source['acknowledged'])))
            return {'seeded': len(request['sources'])}
        if kind == 'fetch':
            scope, identity = request['source_scope'], request['source_delivery_id']
            row = connection.execute('SELECT source_json,acknowledged FROM sources WHERE scope=? AND delivery_id=?',
                                     (scope, identity)).fetchone()
            if row is None:
                raise ValueError('source item is unavailable')
            connection.execute('INSERT INTO calls(kind,scope,delivery_id) VALUES(?,?,?)',
                               ('fetch', scope, identity))
            return {'source': document(row[0])}
        if kind == 'ack':
            scope, identity = request['source_scope'], request['source_delivery_id']
            if not request.get('checkpoint_digest', '').startswith('sha256:') or \
                    not request.get('transfer_digest', '').startswith('sha256:'):
                raise ValueError('acknowledgement lacks committed transfer identity')
            if connection.execute('SELECT COUNT(*) FROM calls WHERE kind=? AND scope=? AND delivery_id=?',
                                  ('fetch', scope, identity)).fetchone()[0] == 0:
                raise ValueError('source acknowledgement preceded provider fetch')
            barrier = connection.execute(
                'SELECT observer_command_json,run_id,operation_id,checkpoint_digest,transfer_digest '
                'FROM acknowledgement_barrier WHERE singleton=1').fetchone()
            if barrier is None or (request['checkpoint_digest'], request['transfer_digest']) != barrier[3:]:
                raise ValueError('acknowledgement differs from driver-bound transfer')
            observed = subprocess.run(json.loads(barrier[0]), input=canonical_json_bytes({
                'kind': 'observe_delivery_state', 'run_id': barrier[1],
                'operation_id': barrier[2], 'transport_database_path': str(path)}),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if observed.returncode:
                raise ValueError('fresh-process durable transfer observation failed before acknowledgement')
            durable = document(observed.stdout)
            if observed.stdout != canonical_json_bytes(durable):
                raise ValueError('noncanonical durable transfer observation')
            after = durable.get('after')
            if type(after) is not dict or after.get('checkpoint', {}).get('execution_checkpoint_digest') != barrier[3] or \
                    barrier[4] not in [item.get('admission_binding_digest') for item in after.get('bindings', [])] + \
                    [item.get('ingress_dead_letter_digest') for item in after.get('dead_letters', [])]:
                raise ValueError('source acknowledgement preceded durable transfer')
            changed = connection.execute('UPDATE sources SET acknowledged=1 WHERE scope=? AND delivery_id=? AND acknowledged=0',
                                         (scope, identity)).rowcount
            if changed != 1:
                raise ValueError('source item cannot be acknowledged twice')
            connection.execute('INSERT INTO calls(kind,scope,delivery_id,checkpoint_digest,transfer_digest) VALUES(?,?,?,?,?)',
                               ('ack', scope, identity, request['checkpoint_digest'],
                                request['transfer_digest']))
            return {'acknowledged': True}
        if kind == 'deliver':
            effect_id, route = request['effect_id'], request['route']
            intent = request['intent']
            if type(intent) is not dict or intent.get('effect_id') != effect_id:
                raise ValueError('destination transfer lacks complete matching intent')
            if route not in ('uncertain', 'accept', 'dead_letter'):
                raise ValueError('unknown test destination route')
            outcome = {'uncertain': 'ambiguous', 'accept': 'confirmed',
                       'dead_letter': 'dead_lettered'}[route]
            receipt = {'accept': 'destination-acceptance-actual-1',
                       'dead_letter': 'destination-dead-letter-actual-1'}.get(route)
            reason = {'uncertain': 'acceptance_unknown',
                      'dead_letter': 'destination_policy_rejected'}.get(route)
            connection.execute('INSERT INTO calls(kind,effect_id,outcome,receipt_id,intent_json) VALUES(?,?,?,?,?)',
                               ('deliver', effect_id, outcome, receipt,
                                canonical_json_bytes(intent)))
            return {'outcome': outcome, 'reason_code': reason,
                    'destination_receipt_id': receipt}
        if kind == 'snapshot':
            sources = [{'source_scope': scope, 'source_delivery_id': identity,
                        'source': document(raw), 'acknowledged': bool(acknowledged)}
                       for scope, identity, raw, acknowledged in connection.execute(
                           'SELECT scope,delivery_id,source_json,acknowledged FROM sources ORDER BY scope,delivery_id')]
            calls = [{'kind': kind, 'source_scope': scope, 'source_delivery_id': identity,
                      'effect_id': effect_id, 'outcome': outcome, 'destination_receipt_id': receipt,
                      'checkpoint_digest': checkpoint_digest, 'transfer_digest': transfer_digest,
                      'intent': None if intent is None else document(intent)}
                     for kind, scope, identity, effect_id, outcome, receipt,
                         checkpoint_digest, transfer_digest, intent in connection.execute(
                         'SELECT kind,scope,delivery_id,effect_id,outcome,receipt_id,checkpoint_digest,transfer_digest,intent_json FROM calls ORDER BY sequence')]
            return {'sources': sources, 'calls': calls}
        raise ValueError('unknown transport operation')


if __name__ == '__main__':
    try:
        response = handle(document(sys.stdin.buffer.read()))
        sys.stdout.buffer.write(canonical_json_bytes(response))
    except (ValueError, KeyError, sqlite3.Error) as error:
        sys.stderr.write(str(error) + '\n')
        sys.exit(1)
