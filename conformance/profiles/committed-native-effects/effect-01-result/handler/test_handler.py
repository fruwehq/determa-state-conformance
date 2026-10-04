"""Tiny native handler fixture; SDK objects remain private to this function."""
from dataclasses import dataclass


@dataclass(frozen=True)
class NativeReply:
    reference: str
    accepted: bool


def invoke(payload, metadata, attempt, call_log):
    # The injected call stands for a destination API with scoped deduplication.
    reply = NativeReply(*call_log.call(metadata['scope_identity'], metadata['effect_id'], payload))
    if not reply.accepted:
        return {'report_kind': 'ambiguous', 'payload': ['map', []],
                'reason': 'provider_acceptance_unknown'}
    return {'report_kind': 'succeeded',
            'payload': ['map', [['provider_reference', ['string', reply.reference]]]],
            'reason': None}
