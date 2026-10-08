"""Fix admin@madps.ai password hash in all MAD-PS SQLite databases."""
import hashlib, hmac, sqlite3
from pathlib import Path

# Generate real PBKDF2 hash of 'admin123' with salt 'default'
SALT = "default"
PASSWORD = "admin123"
dk = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode("utf-8"), SALT.encode("utf-8"), 100_000)
REAL_HASH = f"pbkdf2:sha256:100000${SALT}${dk.hex()}"

print(f"[*] Computed real hash for '{PASSWORD}':")
print(f"    {REAL_HASH[:60]}...")

# Verify the hash works
parts = REAL_HASH.split("$")
verify_dk = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode("utf-8"), parts[1].encode("utf-8"), 100_000)
assert hmac.compare_digest(verify_dk.hex(), parts[2]), "Self-verification failed!"
print("[+] Self-verification passed!")

# Update all DB files found in workspace
ROOT = Path(__file__).parent
updated_any = False
for db_path in ROOT.rglob("mad_ps_product.db"):
    print(f"\n[*] Found DB: {db_path}")
    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        # Check current hash
        cur.execute("SELECT password_hash FROM users WHERE email = ?", ("admin@madps.ai",))
        row = cur.fetchone()
        if row:
            print(f"    Current hash: {row[0][:40]}...")
            cur.execute(
                "UPDATE users SET password_hash = ? WHERE email = ?",
                (REAL_HASH, "admin@madps.ai")
            )
            conn.commit()
            # Re-read to confirm
            cur.execute("SELECT password_hash FROM users WHERE email = ?", ("admin@madps.ai",))
            updated = cur.fetchone()[0]
            print(f"    Updated hash: {updated[:40]}...")
            print(f"    Rows updated: {cur.rowcount if cur.rowcount >= 0 else 'committed'}")
            updated_any = True
        else:
            print("    (no admin@madps.ai user found)")
        conn.close()
    except Exception as e:
        print(f"    ERROR: {e}")

if updated_any:
    print("\n[+] All databases updated successfully!")
    print("[+] You can now sign in with: admin@madps.ai / admin123")
else:
    print("\n[!] No databases were updated. Check paths.")
