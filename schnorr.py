import random
import hashlib


class SchnorrProtocol:
    def __init__(self, p=23, g=5):
        self.p = p # This is the prime modulus
        self.g = g # This is the generator


class Prover:
    # Prover knows secret x and proves it without revealing x
    
    def __init__(self, protocol, secret):
        self.protocol = protocol
        self.x = secret  # Secret key
        self.y = pow(protocol.g, secret, protocol.p)  # Public key: y = g^x mod p
        self.r = None  # Will store random nonce
    
    def commit(self):
        # Generates commitment t = g^r mod p
        self.r = random.randint(1, self.protocol.p - 2)
        t = pow(self.protocol.g, self.r, self.protocol.p)
        return t
    
    def respond(self, challenge):
        # Computes response s = r + c*x mod (p-1)
        s = (self.r + challenge * self.x) % (self.protocol.p - 1)
        return s


class Verifier:
    # Verifier checks proof without learning secret
    
    def __init__(self, protocol, prover_public_key):
        self.protocol = protocol
        self.y = prover_public_key
        self.c = None
    
    def challenge(self):
        # Generates random challenge
        self.c = random.randint(1, self.protocol.p - 2)
        return self.c
    
    def verify(self, commitment, response):
        # Checks if g^s = t * y^c mod p
        lhs = pow(self.protocol.g, response, self.protocol.p)
        rhs = (commitment * pow(self.y, self.c, self.protocol.p)) % self.protocol.p
        return lhs == rhs


def run_protocol():
    protocol = SchnorrProtocol(p=23, g=5)
    print(f"Public Parameters: p={protocol.p}, g={protocol.g}")
    
    prover = Prover(protocol, secret=6)
    print(f"Prover's secret: {prover.x}")
    print(f"Prover's public key: {prover.y}")
    
    verifier = Verifier(protocol, prover.y)
    
    t = prover.commit()
    print(f"Prover commits: t={t}, r={prover.r}")
    
    c = verifier.challenge()
    print(f"Verifier challenges: c={c}")
    
    s = prover.respond(c)
    print(f"Prover responds: s={s}")
    
    valid = verifier.verify(t, s)
    lhs = pow(protocol.g, s, protocol.p)
    rhs = (t * pow(prover.y, c, protocol.p)) % protocol.p
    print(f"Verification: {lhs} = {rhs}, Valid: {valid}")


def schnorr_signature(message, private_key, protocol):
    # Non-interactive signature using Fiat-Shamir
    
    # Commitment
    k = random.randint(1, protocol.p - 2)
    R = pow(protocol.g, k, protocol.p)
    
    # Challenge from hash
    h = hashlib.sha256()
    h.update(str(R).encode() + message.encode())
    e = int(h.hexdigest(), 16) % (protocol.p - 1)
    
    # Response
    s = (k + e * private_key) % (protocol.p - 1)
    
    return (s, e)


def verify_signature(message, signature, public_key, protocol):
    # Verify Schnorr signature
    s, e = signature
    
    # Reconstruct R
    g_s = pow(protocol.g, s, protocol.p)
    y_inv = pow(public_key, protocol.p - 1 - e, protocol.p)
    R = (g_s * y_inv) % protocol.p
    
    # Recompute challenge
    h = hashlib.sha256()
    h.update(str(R).encode() + message.encode())
    e_check = int(h.hexdigest(), 16) % (protocol.p - 1)
    
    return e == e_check

def demo_signature():
    """Demonstrate Schnorr signatures"""
    protocol = SchnorrProtocol()
    private_key = 6
    public_key = pow(protocol.g, private_key, protocol.p)
    
    message = "Hello, Crypto!"
    print(f"Message: {message}")
    print(f"Private key: {private_key}, Public key: {public_key}")
    
    sig = schnorr_signature(message, private_key, protocol)
    print(f"Signature: s={sig[0]}, e={sig[1]}")
    
    valid = verify_signature(message, sig, public_key, protocol)
    tampered = verify_signature("Hello, World!", sig, public_key, protocol)
    print(f"Valid: {valid}, Tampered: {tampered}")

if __name__ == "__main__":
    run_protocol()
    print()
    demo_signature()