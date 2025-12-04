import streamlit as st
import sympy
import random

# --- KONFIGURASI HALAMAN ---
st.set_page_config(page_title="RSA Cryptography Demo", page_icon="🔐", layout="wide")

# --- FUNGSI LOGIKA RSA ---

def generate_keys(bits):
    """
    Menghasilkan pasangan kunci RSA berdasarkan jumlah bit.
    """
    # 1. Generate dua bilangan prima besar p dan q
    # Kita bagi bits dengan 2 agar n mendekati ukuran bits yang diminta
    p = sympy.randprime(2**((bits//2)-1), 2**(bits//2))
    q = sympy.randprime(2**((bits//2)-1), 2**(bits//2))
    
    # Pastikan p != q
    while p == q:
        q = sympy.randprime(2**((bits//2)-1), 2**(bits//2))

    # 2. Hitung n (modulus)
    n = p * q

    # 3. Hitung Euler's totient phi(n)
    phi = (p - 1) * (q - 1)

    # 4. Pilih public exponent (e)
    # Biasanya 65537 adalah pilihan standar yang aman dan efisien
    e = 65537
    # Pastikan gcd(e, phi) == 1, jika tidak, cari yang lain (jarang terjadi dengan 65537)
    while sympy.gcd(e, phi) != 1:
        e = sympy.randprime(3, phi - 1)

    # 5. Hitung private exponent (d)
    # d adalah invers perkalian modular dari e modulo phi
    d = sympy.mod_inverse(e, phi)

    return {
        'p': p, 'q': q, 'n': n, 'phi': phi, 'e': e, 'd': d
    }

def encrypt_message(message, public_key):
    """
    Enkripsi pesan (string) menjadi list integer.
    c = m^e mod n
    """
    n, e = public_key
    encrypted_chars = []
    for char in message:
        # Ubah char ke ASCII/Unicode integer, lalu pangkatkan
        m = ord(char)
        c = pow(m, e, n)
        encrypted_chars.append(c)
    return encrypted_chars

def decrypt_message(ciphertext, private_key):
    """
    Dekripsi list integer kembali menjadi string.
    m = c^d mod n
    """
    n, d = private_key
    decrypted_chars = []
    for c in ciphertext:
        m = pow(c, d, n)
        decrypted_chars.append(chr(m))
    return "".join(decrypted_chars)

# --- STATE MANAGEMENT ---
# Menyimpan kunci dan pesan di session state agar tidak hilang saat navigasi
if 'keys' not in st.session_state:
    st.session_state['keys'] = None
if 'ciphertext' not in st.session_state:
    st.session_state['ciphertext'] = None
if 'plaintext_input' not in st.session_state:
    st.session_state['plaintext_input'] = ""

# --- UI SIDEBAR ---
st.sidebar.title("Navigation")
st.sidebar.write("Go to")
page = st.sidebar.radio("Section", ["Key Generation", "Encryption", "Decryption & Verification"], label_visibility="collapsed")

st.sidebar.markdown("---")
st.sidebar.info("💡 **Tip:** Navigate through sections using the sidebar.")

# --- HALAMAN UTAMA ---

st.title("🔐 RSA Cryptography")
st.markdown("This application demonstrates the basic principles of RSA encryption and decryption.")

# --- 1. KEY GENERATION ---
if page == "Key Generation":
    st.header("1. Key Generation 🔑")
    st.write("Generate a pair of public and private RSA keys. The larger the key size, the more secure, but longer it takes to generate.")

    bits = st.slider("Select Key Size (bits)", min_value=128, max_value=2048, value=512, step=128)
    st.caption(f"This will generate two primes of {bits//2} bits each, resulting in an `n` of approximately {bits} bits.")

    if st.button("Generate RSA Key Pair", type="primary"):
        with st.spinner("Generating primes and calculating keys..."):
            keys = generate_keys(bits)
            st.session_state['keys'] = keys
            st.session_state['ciphertext'] = None # Reset pesan lama jika kunci baru dibuat
        
        st.success("Keys generated successfully!")

    # Tampilkan kunci jika sudah ada
    if st.session_state['keys']:
        keys = st.session_state['keys']
        
        st.info(f"**Step 1:** Generating two large prime numbers (p and q)...\n\n"
                f"**Generated p =** {keys['p']}\n\n**Generated q =** {keys['q']}")
        
        st.info(f"**Step 2:** Calculate n = p * q = \n{keys['n']}\n\n"
                f"**Step 3:** Calculate Euler's totient function phi(n) = (p-1)*(q-1) = \n{keys['phi']}")

        st.info(f"**Step 4:** Choose public exponent (e) such that 1 < e < phi and gcd(e, phi) = 1.\n\n"
                f"**Public exponent (e) =** {keys['e']}")

        st.info(f"**Step 5:** Calculate private exponent (d) as the modular multiplicative inverse of e modulo phi.\n\n"
                f"**Private exponent (d) =** {keys['d']}")

        st.subheader("Generated Keys:")
        
        st.markdown("**Public Key (n, e):**")
        st.code(f"n = {keys['n']}\ne = {keys['e']}")

        st.markdown("**Private Key (n, d):**")
        st.code(f"n = {keys['n']}\nd = {keys['d']}")
        
        st.warning("🚨 Keep your private key secret!")

# --- 2. ENCRYPTION ---
elif page == "Encryption":
    st.header("2. Encryption 🔒")
    
    if not st.session_state['keys']:
        st.warning("⚠️ Please generate keys in the 'Key Generation' tab first.")
    else:
        st.write("Enter the message you want to encrypt using the generated public key.")
        
        keys = st.session_state['keys']
        
        # Tampilkan Public Key
        with st.container():
            st.info(f"**Current Public Key:**\n\n(n={keys['n']},\n\ne={keys['e']})")

        # Input Pesan
        plaintext = st.text_area("Plaintext Message", value=st.session_state['plaintext_input'], height=100)
        
        if st.button("Encrypt Message", type="primary"):
            if plaintext:
                st.session_state['plaintext_input'] = plaintext # Simpan input
                cipher = encrypt_message(plaintext, (keys['n'], keys['e']))
                st.session_state['ciphertext'] = cipher
                st.success("Message encrypted successfully!")
            else:
                st.error("Please enter a message.")

        # Tampilkan Hasil Enkripsi
        if st.session_state['ciphertext']:
            st.subheader("Encrypted Message:")
            st.code(str(st.session_state['ciphertext']), language=None)
            st.info("This is a list of integers, each representing an encrypted character.")

# --- 3. DECRYPTION ---
elif page == "Decryption & Verification":
    st.header("3. Decryption & Verification ✅")

    if not st.session_state['keys']:
        st.warning("⚠️ Please generate keys first.")
    elif not st.session_state['ciphertext']:
        st.warning("⚠️ No encrypted message found. Please encrypt a message in the previous step.")
    else:
        st.write("The encrypted message from the previous step will be used automatically for decryption.")

        keys = st.session_state['keys']

        # Tampilkan Private Key
        with st.container():
            st.info(f"**Current Private Key:**\n\n(n={keys['n']},\n\nd={keys['d']})")
        
        st.markdown("**Encrypted Message to Decrypt:**")
        st.code(str(st.session_state['ciphertext']), language=None)

        if st.button("Decrypt Message", type="primary"):
            decrypted_text = decrypt_message(st.session_state['ciphertext'], (keys['n'], keys['d']))
            
            st.success("Message decrypted successfully!")
            
            st.subheader("Decrypted Message:")
            st.code(decrypted_text, language=None)

            # Verification logic
            st.subheader("Verification")
            original_msg = st.session_state['plaintext_input']
            
            if decrypted_text == original_msg:
                st.success("🎉 Verification: Decryption Successful! The original message matches the decrypted message.")
            else:
                st.error("❌ Verification Failed: The message does not match.")

# --- FOOTER ---
st.markdown("---")
st.caption("Note: This is a simplified RSA implementation for educational purposes. Real-world RSA implementations use more complex padding schemes (e.g., OAEP) and typically encrypt symmetric keys (which then encrypt the message) rather than raw messages directly. Character-by-character encryption as done here is inefficient and has security limitations.")