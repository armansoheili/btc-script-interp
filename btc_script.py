#!/usr/bin/env python3
"""Minimal Bitcoin Script interpreter in pure Python (a stack machine).

Implements the classic stack opcodes, arithmetic / logic opcodes,
control flow (OP_IF / OP_ELSE / OP_ENDIF) and OP_SHA256, so hash-lock
puzzles and conditional scripts can be executed exactly like Bitcoin
does it. Zero dependencies, standard library only.

Doctests:
>>> ok, stack = run_script(assemble("OP_2 OP_3 OP_ADD OP_5 OP_EQUAL"))
>>> ok and decode_num(stack[0])
1
>>> ok, stack = run_script(assemble("OP_1 OP_IF 10 OP_ELSE 20 OP_ENDIF"))
>>> ok and decode_num(stack[0])
10
"""

import hashlib

# --------------------------------------------------------------------------
# Script numbers (little-endian, sign bit in the MSB of the last byte)
# --------------------------------------------------------------------------

def encode_num(n):
    """Encode a signed int as a Bitcoin script number.

    >>> encode_num(0)
    b''
    >>> encode_num(127)
    b'\\x7f'
    >>> encode_num(128)
    b'\\x80\\x00'
    >>> encode_num(-1)
    b'\\x81'
    >>> decode_num(encode_num(-123456)) == -123456
    True
    """
    if n == 0:
        return b""
    neg = n < 0
    n = abs(n)
    b = bytearray(n.to_bytes((n.bit_length() + 7) // 8, "little"))
    if b[-1] & 0x80:
        b.append(0)
    if neg:
        b[-1] |= 0x80
    return bytes(b)


def decode_num(b):
    """Decode a Bitcoin script number to a signed int.

    >>> decode_num(b'')
    0
    >>> decode_num(b'\\x81')
    -1
    >>> decode_num(b'\\x80\\x00')
    128
    """
    if not b:
        return 0
    b = bytearray(b)
    neg = b[-1] & 0x80
    b[-1] &= 0x7F
    n = int.from_bytes(bytes(b), "little")
    return -n if neg else n


# --------------------------------------------------------------------------
# Assembler: human-readable text <-> script bytes
# --------------------------------------------------------------------------

OPCODES = {
    "OP_0": 0x00, "OP_FALSE": 0x00,
    "OP_PUSHDATA1": 0x4C, "OP_PUSHDATA2": 0x4D, "OP_PUSHDATA4": 0x4E,
    "OP_1NEGATE": 0x4F, "OP_RESERVED": 0x50,
    "OP_1": 0x51, "OP_TRUE": 0x51, "OP_2": 0x52, "OP_3": 0x53, "OP_4": 0x54,
    "OP_5": 0x55, "OP_6": 0x56, "OP_7": 0x57, "OP_8": 0x58, "OP_9": 0x59,
    "OP_10": 0x5A, "OP_11": 0x5B, "OP_12": 0x5C, "OP_13": 0x5D,
    "OP_14": 0x5E, "OP_15": 0x5F, "OP_16": 0x60,
    "OP_NOP": 0x61, "OP_IF": 0x63, "OP_NOTIF": 0x64, "OP_ELSE": 0x67,
    "OP_ENDIF": 0x68, "OP_VERIFY": 0x69, "OP_RETURN": 0x6A,
    "OP_2DROP": 0x6D, "OP_2DUP": 0x6E, "OP_3DUP": 0x6F, "OP_2OVER": 0x70,
    "OP_2ROT": 0x71, "OP_2SWAP": 0x72, "OP_IFDUP": 0x73, "OP_DEPTH": 0x74,
    "OP_DROP": 0x75, "OP_DUP": 0x76, "OP_NIP": 0x77, "OP_OVER": 0x78,
    "OP_PICK": 0x79, "OP_ROLL": 0x7A, "OP_ROT": 0x7B, "OP_SWAP": 0x7C,
    "OP_TUCK": 0x7D, "OP_EQUAL": 0x87, "OP_EQUALVERIFY": 0x88,
    "OP_1ADD": 0x89, "OP_1SUB": 0x8A, "OP_NEGATE": 0x8B, "OP_ABS": 0x8C,
    "OP_NOT": 0x8D, "OP_0NOTEQUAL": 0x8E, "OP_ADD": 0x93, "OP_SUB": 0x94,
    "OP_MUL": 0x95, "OP_DIV": 0x96, "OP_MOD": 0x97,
    "OP_BOOLAND": 0x9A, "OP_BOOLOR": 0x9B, "OP_NUMEQUAL": 0x9C,
    "OP_NUMEQUALVERIFY": 0x9D, "OP_NUMNOTEQUAL": 0x9E,
    "OP_LESSTHAN": 0xA0, "OP_GREATERTHAN": 0xA1,
    "OP_LESSTHANOREQUAL": 0xA2, "OP_GREATERTHANOREQUAL": 0xA3,
    "OP_MIN": 0xA4, "OP_MAX": 0xA5, "OP_WITHIN": 0xA6, "OP_SHA256": 0xA8,
}

OP_NAMES = {v: k for k, v in OPCODES.items()}


def _push(data):
    n = len(data)
    if n == 0:
        return b"\x00"
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + data
    if n <= 0xFFFF:
        return b"\x4d" + n.to_bytes(2, "little") + data
    return b"\x4e" + n.to_bytes(4, "little") + data


def assemble(text):
    """Compile assembly text into script bytes.

    Tokens: OP_* names, integers (script numbers), or 0x-prefixed raw
    hex data pushes.

    >>> assemble("OP_2 OP_3 OP_ADD").hex()
    '525393'
    >>> disassemble(assemble("OP_2 OP_3 OP_ADD"))
    'OP_2 OP_3 OP_ADD'
    """
    out = bytearray()
    for tok in text.split():
        if tok in OPCODES:
            out.append(OPCODES[tok])
        elif tok.startswith("0x"):
            out += _push(bytes.fromhex(tok[2:]))
        elif tok.lstrip("+-").isdigit():
            out += _push(encode_num(int(tok)))
        else:
            raise ValueError("unknown token: %r" % tok)
    return bytes(out)


def disassemble(script):
    """Render script bytes as assembly text.

    >>> disassemble(bytes.fromhex("527687"))
    'OP_2 OP_DUP OP_EQUAL'
    """
    tokens = []
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op in OP_NAMES:
            tokens.append(OP_NAMES[op])
        elif op <= 0x4B:          # direct push
            data = script[i:i + op]
            i += op
            tokens.append("0x" + data.hex())
        elif op == 0x4C:
            n = script[i]; data = script[i + 1:i + 1 + n]; i += 1 + n
            tokens.append("0x" + data.hex())
        else:
            tokens.append("<opcode 0x%02x>" % op)
    return " ".join(tokens)


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------

class ScriptError(Exception):
    pass


def _cast_to_bool(b):
    """Bitcoin's CastToBool: any nonzero byte (ignoring sign bit) is true."""
    for i, byte in enumerate(b):
        if byte & 0xFF:
            if i == len(b) - 1 and byte == 0x80:
                return False
            return True
    return False


def run_script(script, stack=()):
    """Execute script bytes. Returns (ok, final_stack).

    >>> ok, s = run_script(assemble("OP_1 OP_2 OP_ADD OP_3 OP_EQUAL"))
    >>> ok, decode_num(s[0])
    (True, 1)
    >>> ok, _ = run_script(assemble("OP_1 OP_0 OP_ADD OP_2 OP_EQUAL"))
    >>> ok
    False
    """
    stack = [bytes(x) for x in stack]
    pc, n = 0, len(script)
    cond = []  # conditional execution flags (True = this branch runs)

    def executing():
        return all(cond)

    def pop():
        if not stack:
            raise ScriptError("stack underflow")
        return stack.pop()

    while pc < n:
        op = script[pc]
        pc += 1

        # data pushes
        if op <= 0x4B:
            if executing():
                if pc + op > n:
                    raise ScriptError("truncated push")
                stack.append(script[pc:pc + op])
                pc += op
            else:
                pc += op
            continue

        # control flow always processed
        if op == 0x63:      # OP_IF
            v = _cast_to_bool(pop()) if executing() else False
            cond.append(v)
            continue
        if op == 0x64:      # OP_NOTIF
            v = (not _cast_to_bool(pop())) if executing() else False
            cond.append(v)
            continue
        if op == 0x67:      # OP_ELSE
            if not cond:
                raise ScriptError("OP_ELSE without OP_IF")
            cond[-1] = not cond[-1]
            continue
        if op == 0x68:      # OP_ENDIF
            if not cond:
                raise ScriptError("OP_ENDIF without OP_IF")
            cond.pop()
            continue
        if not executing():
            continue

        # --- stack ops --------------------------------------------------
        if op == 0x61:   # OP_NOP
            pass
        elif op == 0x69:  # OP_VERIFY
            if not _cast_to_bool(pop()):
                raise ScriptError("OP_VERIFY failed")
        elif op == 0x6A:  # OP_RETURN
            raise ScriptError("OP_RETURN")
        elif op == 0x6D:  # OP_2DROP
            pop(); pop()
        elif op == 0x6E:  # OP_2DUP
            a, b = pop(), pop()
            stack += [b, a, b, a]
        elif op == 0x74:  # OP_DEPTH
            stack.append(encode_num(len(stack)))
        elif op == 0x75:  # OP_DROP
            pop()
        elif op == 0x76:  # OP_DUP
            a = pop(); stack += [a, a]
        elif op == 0x78:  # OP_OVER
            a, b = pop(), pop(); stack += [b, a, b]
        elif op == 0x7B:  # OP_ROT
            a, b, c = pop(), pop(), pop(); stack += [b, a, c]
        elif op == 0x7C:  # OP_SWAP
            a, b = pop(), pop(); stack += [a, b]
        # --- numeric ops ------------------------------------------------
        elif op == 0x8B:  # OP_NEGATE
            stack.append(encode_num(-decode_num(pop())))
        elif op == 0x8C:  # OP_ABS
            stack.append(encode_num(abs(decode_num(pop()))))
        elif op == 0x8D:  # OP_NOT
            stack.append(b"" if _cast_to_bool(pop()) else b"\x01")
        elif op == 0x93:  # OP_ADD
            a, b = decode_num(pop()), decode_num(pop())
            stack.append(encode_num(b + a))
        elif op == 0x94:  # OP_SUB
            a, b = decode_num(pop()), decode_num(pop())
            stack.append(encode_num(b - a))
        elif op == 0x95:  # OP_MUL
            a, b = decode_num(pop()), decode_num(pop())
            stack.append(encode_num(b * a))
        elif op == 0x96:  # OP_DIV
            a = decode_num(pop())
            if a == 0:
                raise ScriptError("OP_DIV by zero")
            b = decode_num(pop())
            stack.append(encode_num(int(b / a)))
        # --- logic / compare ops ----------------------------------------
        elif op == 0x87:  # OP_EQUAL
            a, b = pop(), pop()
            stack.append(b"\x01" if a == b else b"")
        elif op == 0x88:  # OP_EQUALVERIFY
            a, b = pop(), pop()
            if a != b:
                raise ScriptError("OP_EQUALVERIFY failed")
        elif op == 0x9A:  # OP_BOOLAND
            a, b = pop(), pop()
            stack.append(b"\x01" if _cast_to_bool(a) and _cast_to_bool(b) else b"")
        elif op == 0x9B:  # OP_BOOLOR
            a, b = pop(), pop()
            stack.append(b"\x01" if _cast_to_bool(a) or _cast_to_bool(b) else b"")
        elif op == 0x9C:  # OP_NUMEQUAL
            a, b = decode_num(pop()), decode_num(pop())
            stack.append(b"\x01" if a == b else b"")
        elif op == 0xA0:  # OP_LESSTHAN
            a, b = decode_num(pop()), decode_num(pop())
            stack.append(b"\x01" if b < a else b"")
        elif op == 0xA1:  # OP_GREATERTHAN
            a, b = decode_num(pop()), decode_num(pop())
            stack.append(b"\x01" if b > a else b"")
        elif op == 0xA4:  # OP_MIN
            a, b = decode_num(pop()), decode_num(pop())
            stack.append(encode_num(min(a, b)))
        elif op == 0xA5:  # OP_MAX
            a, b = decode_num(pop()), decode_num(pop())
            stack.append(encode_num(max(a, b)))
        elif op == 0xA6:  # OP_WITHIN: x min max -> min <= x < max
            mx = decode_num(pop()); mn = decode_num(pop()); x = decode_num(pop())
            stack.append(b"\x01" if mn <= x < mx else b"")
        # --- crypto ------------------------------------------------------
        elif op == 0xA8:  # OP_SHA256
            stack.append(hashlib.sha256(pop()).digest())
        # --- small ints ---------------------------------------------------
        elif op == 0x00:
            stack.append(b"")
        elif op == 0x4F:
            stack.append(encode_num(-1))
        elif 0x51 <= op <= 0x60:
            stack.append(encode_num(op - 0x50))
        else:
            raise ScriptError("unknown opcode 0x%02x" % op)

    if cond:
        raise ScriptError("unbalanced OP_IF/OP_ENDIF")
    top_true = bool(stack) and _cast_to_bool(stack[-1])
    return top_true, stack


def verify(spend_hex, redeem_asm):
    """Check a classic input/output pair: spend script then redeem script.

    spend_hex is a hex-encoded push-only scriptSig, redeem_asm the
    assembly of the locking script.

    >>> secret = b"satoshi"
    >>> h = hashlib.sha256(secret).hexdigest()
    >>> spend = "%02x%s" % (len(secret), secret.hex())   # <7> <satoshi>
    >>> verify(spend, "OP_SHA256 0x" + h + " OP_EQUAL")
    True
    >>> bad = "%02x%s" % (len(b"woope"), b"woope".hex())
    >>> verify(bad, "OP_SHA256 0x" + h + " OP_EQUAL")
    False
    """
    sig = []
    pc, raw = 0, bytes.fromhex(spend_hex)
    while pc < len(raw):
        op = raw[pc]; pc += 1
        if op <= 0x4B:
            sig.append(raw[pc:pc + op]); pc += op
        else:
            raise ValueError("spend script must be push-only")
    ok, _ = run_script(assemble(redeem_asm), stack=sig)
    return ok


def _demo():
    print("== hash-lock puzzle ==")
    secret = b"satoshi"
    digest = hashlib.sha256(secret).hexdigest()
    redeem = "OP_SHA256 0x%s OP_EQUAL" % digest
    print("redeem script :", disassemble(assemble(redeem)))
    print("correct secret:", verify("%02x%s" % (len(secret), secret.hex()), redeem))
    print("wrong secret  :", verify("%02x%s" % (len(b"ethereum"), b"ethereum".hex()), redeem))

    print("\n== conditional script ==")
    for choice in (1, 0):
        # <choice> OP_IF <true-branch> OP_ELSE <false-branch> OP_ENDIF
        full = "0x%02x OP_IF 100 OP_ELSE 200 OP_ENDIF" % choice
        ok, st = run_script(assemble(full))
        print("choice=%d -> stack top =" % choice, decode_num(st[0]), "| valid:", ok)

    print("\n== arithmetic puzzle: (x * 7 - 2) == 40 ==")
    # solver pushes x; script checks the constraint
    ok, st = run_script(assemble("0x06 OP_DUP 7 OP_MUL 2 OP_SUB 40 OP_NUMEQUAL"))
    print("x=6 solves it:", ok, "| top of stack:", decode_num(st[0]))


def _test():
    import doctest
    r = doctest.testmod(verbose=False)
    print("doctests: %d passed, %d failed" % (r.attempted - r.failed, r.failed))
    if r.failed:
        raise SystemExit(1)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        _test()
    else:
        _demo()
