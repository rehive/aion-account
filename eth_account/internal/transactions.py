import itertools
import time

from cytoolz import (
    curry,
    dissoc,
    identity,
    merge,
    partial,
    pipe,
)
from eth_rlp import (
    HashableRLP,
)
from eth_utils.curried import (
    apply_formatters_to_dict,
    apply_one_of_formatters,
    hexstr_if_str,
    is_0x_prefixed,
    is_bytes,
    is_checksum_address,
    is_integer,
    is_string,
    to_bytes,
    to_int,
)
import rlp
from rlp.sedes import (
    Binary,
    BigEndianInt,
    big_endian_int,
    binary,
)
import hexbytes


def serializable_unsigned_transaction_from_dict(transaction_dict):
    assert_valid_fields(transaction_dict)
    filled_transaction = pipe(
        transaction_dict,
        dict,
        partial(merge, TRANSACTION_DEFAULTS),
        chain_id_to_v,
        apply_formatters_to_dict(TRANSACTION_FORMATTERS),
    )
    if 'v' in filled_transaction:
        serializer = Transaction
    else:
        serializer = UnsignedTransaction
    return serializer.from_dict(filled_transaction)


def encode_transaction(unsigned_transaction, vrs):
    (v, r, s, sig_bytes, total_sig) = vrs
    print(unsigned_transaction)
    print(unsigned_transaction.as_dict())
    chain_naive_transaction = dissoc(unsigned_transaction.as_dict(), 'v', 'r', 's')
    print('THE SIG BYTES')
    print(len(sig_bytes))
    print(sig_bytes[1:])
    signed_transaction = Transaction(s=sig_bytes, **chain_naive_transaction)
    print(signed_transaction.as_dict())
    return rlp.encode(signed_transaction)


def is_int_or_prefixed_hexstr(val):
    if is_integer(val):
        return True
    elif isinstance(val, str) and is_0x_prefixed(val):
        return True
    else:
        return False


def is_empty_or_checksum_address(val):
    if val in {None, b'', ''}:
        return True
    elif is_checksum_address(val):
        return True
    else:
        return False


def is_none(val):
    return val is None


def int_to_hex(val):
    return bytes(hex(val), encoding='utf-8')


TRANSACTION_DEFAULTS = {
    'to': b'',
    'value': b'R\x08',
    'data': b'',
    'tx_type': b'\x01',
    'timestamp': bytes(hexbytes.HexBytes(int(time.time()*1000.0))),
    'gasPrice': b'R\x08'
}

TRANSACTION_FORMATTERS = {
    # 'nonce': hexstr_if_str(to_int),
    # 'gas': hexstr_if_str(to_int),
    # 'gasPrice': apply_one_of_formatters((
    #     (is_string, hexstr_if_str(to_bytes)),
    #     (is_bytes, identity),
    #     (is_none, lambda val: b''),
    # )),
    'to': apply_one_of_formatters((
        (is_string, hexstr_if_str(to_bytes)),
        (is_bytes, identity),
        (is_none, lambda val: b''),
    )),
    # 'value': hexstr_if_str(to_int),
    'data': hexstr_if_str(to_bytes),
    'v': hexstr_if_str(to_int),
    'r': hexstr_if_str(to_int),
    's': apply_one_of_formatters((
        (is_string, hexstr_if_str(to_bytes)),
        (is_bytes, identity),
        (is_none, lambda val: b''),
    )),
}

TRANSACTION_VALID_VALUES = {
    'nonce': lambda val: isinstance(val, (int, str, bytes, bytearray)),
    'gasPrice': is_int_or_prefixed_hexstr,
    'gas': lambda val: isinstance(val, (int, str, bytes, bytearray)),
    'to': is_empty_or_checksum_address,
    'value': is_int_or_prefixed_hexstr,
    'data': lambda val: isinstance(val, (int, str, bytes, bytearray)),
    'chainId': lambda val: val is None or is_int_or_prefixed_hexstr(val),
}

ALLOWED_TRANSACTION_KEYS = {
    'nonce',
    'gasPrice',
    'gas',
    'to',
    'value',
    'data',
    'tx_type',
    'timestamp',
    'chainId',  # set chainId to None if you want a transaction that can be replayed across networks
}

REQUIRED_TRANSACITON_KEYS = ALLOWED_TRANSACTION_KEYS.difference(TRANSACTION_DEFAULTS.keys())


def assert_valid_fields(transaction_dict):
    # check if any keys are missing
    missing_keys = REQUIRED_TRANSACITON_KEYS.difference(transaction_dict.keys())
    if missing_keys:
        raise TypeError("Transaction must include these fields: %r" % missing_keys)

    # check if any extra keys were specified
    superfluous_keys = set(transaction_dict.keys()).difference(ALLOWED_TRANSACTION_KEYS)
    if superfluous_keys:
        raise TypeError("Transaction must not include unrecognized fields: %r" % superfluous_keys)

    # check for valid types in each field
    valid_fields = apply_formatters_to_dict(TRANSACTION_VALID_VALUES, transaction_dict)
    if not all(valid_fields.values()):
        invalid = {key: transaction_dict[key] for key, valid in valid_fields.items() if not valid}
        raise TypeError("Transaction had invalid fields: %r" % invalid)


def chain_id_to_v(transaction_dict):
    # See EIP 155
    chain_id = transaction_dict.pop('chainId')
    if chain_id is None:
        return transaction_dict
    else:
        return dict(transaction_dict, v=chain_id, r=0, s=0)


@curry
def fill_transaction_defaults(transaction):
    return merge(TRANSACTION_DEFAULTS, transaction)


UNSIGNED_TRANSACTION_FIELDS = (
    ('nonce', binary),
    ('to', Binary.fixed_length(32, allow_empty=True)),
    ('value', binary),
    ('data', binary),
    ('timestamp', binary),
    ('gas', binary),
    ('gasPrice', binary),
    ('tx_type', binary),
)


class Transaction(HashableRLP):
    fields = UNSIGNED_TRANSACTION_FIELDS + (
        ('s',  Binary.fixed_length(96, allow_empty=True)),
        # ('sv', Binary.fixed_length(64, allow_empty=True)),
    )


class UnsignedTransaction(HashableRLP):
    fields = UNSIGNED_TRANSACTION_FIELDS


ChainAwareUnsignedTransaction = Transaction


def strip_signature(txn):
    unsigned_parts = itertools.islice(txn, len(UNSIGNED_TRANSACTION_FIELDS))
    return list(unsigned_parts)


def vrs_from(transaction):
    return (getattr(transaction, part) for part in 'vrs')
