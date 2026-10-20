# btc-script-interp

A minimal Bitcoin Script interpreter in pure Python — a faithful little stack
machine for the language that locks and unlocks every Bitcoin output.

Implemented opcodes:

- **Stack**: `OP_DUP`, `OP_DROP`, `OP_2DROP`, `OP_SWAP`, `OP_OVER`, `OP_ROT`, `OP_2DUP`, `OP_DEPTH`
- **Arithmetic**: `OP_ADD`, `OP_SUB`, `OP_MUL`, `OP_DIV`, `OP_NEGATE`, `OP_ABS`
- **Logic / comparison**: `OP_EQUAL`, `OP_EQUALVERIFY`, `OP_NUMEQUAL`, `OP_LESSTHAN`, `OP_GREATERTHAN`, `OP_MIN`, `OP_MAX`, `OP_WITHIN`, `OP_NOT`, `OP_BOOLAND`, `OP_BOOLOR`
- **Control flow**: `OP_IF` / `OP_NOTIF` / `OP_ELSE` / `OP_ENDIF`, `OP_VERIFY`, `OP_RETURN`
- **Crypto**: `OP_SHA256`

Plus a small assembler/disassembler and Bitcoin's script-number encoding
(little-endian, sign bit in the most-significant byte).

## Usage

```bash
python btc_script.py          # run the demo (hash-lock puzzle, conditional, arithmetic)
python btc_script.py --test   # run the doctests
```

### Example: a hash-lock puzzle

```python
from btc_script import verify
import hashlib

secret = b"satoshi"
digest = hashlib.sha256(secret).hexdigest()
redeem = "OP_SHA256 0x%s OP_EQUAL" % digest

verify("0x" + secret.hex(), redeem)     # True
verify("0x" + b"wrong".hex(), redeem)   # False
```

### Example: inline scripts

```python
from btc_script import assemble, run_script, decode_num

ok, stack = run_script(assemble("OP_1 OP_IF 100 OP_ELSE 200 OP_ENDIF"))
print(ok, decode_num(stack[0]))  # True 100
```

## Notes

- Script numbers use Bitcoin's encoding: `0x81` is `-1`, `0x8000` is `128`.
- OP_CHECKSIG is intentionally out of scope; signature checks live in the
  [`ecdsa-secp256k1`](https://github.com/armansoheili/ecdsa-secp256k1) repo.
- Zero dependencies — only Python's standard library.

MIT license.
