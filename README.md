# Schnorr's Protocol Implementation

A educational implementation of Schnorr's identification protocol and digital signature scheme in Python.

## What is Schnorr's Protocol?

Schnorr's Protocol is a **zero-knowledge proof** that allows a prover to demonstrate knowledge of a discrete logarithm without revealing it. It's a fundamental building block in modern cryptography.

### Key Properties:
- **Zero-Knowledge:** Verifier learns nothing about the secret
- **Soundness:** Cannot fake a proof without knowing the secret
- **Completeness:** Honest provers always pass verification

## How It Works

### Interactive Protocol (4 Steps)

1. **Commitment:** Prover sends a random $r$ such that $t = g^r \mod p$
2. **Challenge:** Verifier sends random $c$
3. **Response:** Prover sends $s = r + c \cdot x$
4. **Verification:** Verifier checks $g^s = t \cdot y^c \mod p$

### Mathematical Foundation

Given public parameters $(p, g, y)$ where $y = g^x \mod p$, the prover demonstrates knowledge of secret $x$ without revealing it.

The verification equation holds because:
$$
\begin{split}
g^s &= g^{r + c \cdot x} \\
    &= g^r \cdot (g^x)^c \\
    &= t \cdot y^c
\end{split}
$$

## Installation

```bash
git clone 
cd schnorr-protocol
python schnorr.py
```

## Usage

### Interactive Protocol

```python
from schnorr import SchnorrProtocol, Prover, Verifier

protocol = SchnorrProtocol(p=23, g=5)
prover = Prover(protocol, secret=6)
verifier = Verifier(protocol, prover.y)

t = prover.commit()
c = verifier.challenge()
s = prover.respond(c)
valid = verifier.verify(t, s)
```

### Digital Signatures (Non-Interactive)

```python
from schnorr import schnorr_signature, verify_signature

protocol = SchnorrProtocol()
private_key = 6
public_key = pow(protocol.g, private_key, protocol.p)

# Sign
message = "Hello, Crypto!"
signature = schnorr_signature(message, private_key, protocol)

# Verify
is_valid = verify_signature(message, signature, public_key, protocol)
```

## Code Structure

```
schnorr.py
├── SchnorrProtocol      # Protocol parameters (p, g)
├── Prover               # Generates commitments and responses
├── Verifier             # Issues challenges and verifies proofs
├── schnorr_signature    # Non-interactive signing (Fiat-Shamir)
└── verify_signature     # Signature verification
```

## Example Output

```
Public Parameters: p=23, g=5
Prover's secret: 6
Prover's public key: 8
Prover commits: t=21, r=13
Verifier challenges: c=5
Prover responds: s=21
Verification: 14 = 14, Valid: True

Message: Hello, Crypto!
Private key: 6, Public key: 8
Signature: s=12, e=7
Valid: True, Tampered: False
```

## Security Notes

This is for **Educational Use Only**.

This implementation uses small primes (p=23) for clarity and demonstration. For production use:

- Use primes of 2048+ bits
- Use cryptographic libraries (e.g., `cryptography`, `pycryptodome`)
- Use secure random number generation (`secrets` module)
- Consider standardized curves (Ed25519, secp256k1)

## Applications

Schnorr's Protocol is used in:

- **Bitcoin (Taproot):** Schnorr signatures for better privacy and efficiency
- **EdDSA/Ed25519:** Modern signature scheme used in SSH, Signal, cryptocurrencies
- **Multi-signatures:** MuSig protocol for signature aggregation
- **Authentication:** Zero-knowledge identification systems
- **Blockchain:** Consensus mechanisms and privacy protocols

## Key Concepts

### Discrete Logarithm Problem
Security relies on the hardness of finding $x$ given $y = g^x \mod p$. This is computationally infeasible for large primes.

### Fiat-Shamir Heuristic
Transforms the interactive protocol into non-interactive signatures by replacing the verifier's challenge with a hash:
```
c = Hash(t || message)
```

### Zero-Knowledge Property
A simulator can generate valid-looking transcripts without knowing the secret, proving that real transcripts leak no information about $x$.

## References

- **Original Paper -** C.P. Schnorr, "Efficient Identification and Signatures for Smart Cards" (1989).
- **"Schnorr signature" -** Wikipedia. https://en.wikipedia.org/wiki/Schnorr_signature
- **"Cryptoshorts e02: Schnorr Signature" -** A Youtube video made by the channel Cryptoshorts. https://www.youtube.com/watch?v=r9hJiDrtukI

## License

MIT License - Free for educational and research purposes.
