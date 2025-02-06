import ecdsa
from sympy import mod_inverse

def detect_vulnerability(min_k, max_k):
    k_range = max_k - min_k + 1
    
    if k_range <= 20:  # Agar k-values bohot kam range me hain
        return "HIGH", "Poor Randomness (RNG Weakness)"
    elif k_range <= 50:
        return "MEDIUM", "Potential Weak k-values"
    else:
        return "LOW", "No major vulnerability detected"

def recover_private_key(signatures, min_k, max_k):
    order = ecdsa.SECP256k1.order
    equations = []
    results = []

    for i in range(len(signatures) - 1):
        (r1, s1), (r2, s2) = signatures[i], signatures[i + 1]
        if r1 == r2:  # Reused Nonce Attack
            num = (s1 - s2) % order
            denom = mod_inverse((s1 * s2) % order, order)
            private_key = (num * denom) % order
            print(f"Private Key Found: {hex(private_key)}")
            with open("found.txt", "a") as f:
                f.write(f"Private Key: {hex(private_key)}\n")
            return private_key

    return None

def main():
    min_k = int(input("Enter Min Nonce (k) in hex: "), 16)
    max_k = int(input("Enter Max Nonce (k) in hex: "), 16)

    severity, reason = detect_vulnerability(min_k, max_k)

    print(f"\nVulnerability Report:")
    print(f"Min Nonce (k): {hex(min_k)}")
    print(f"Max Nonce (k): {hex(max_k)}")
    print(f"Private Key Extractable: {severity} ({reason})")

    if severity in ["HIGH", "MEDIUM"]:
        choice = input("\nDo you have signatures (r, s) data? (y/n): ").strip().lower()
        if choice == 'y':
            signatures = []
            num_signatures = int(input("Enter number of signatures: "))
            for _ in range(num_signatures):
                r = int(input("Enter r value in hex: "), 16)
                s = int(input("Enter s value in hex: "), 16)
                signatures.append((r, s))
            
            print("\nAttempting Private Key Extraction...")
            private_key = recover_private_key(signatures, min_k, max_k)
            if private_key:
                print(f"Private Key Recovered: {hex(private_key)}")
            else:
                print("Private Key Extraction Failed.")
        else:
            print("Signature data not provided. Cannot extract Private Key.")

if __name__ == "__main__":
    main()
