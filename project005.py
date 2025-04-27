import streamlit as st  # type: ignore
import hashlib
from cryptography.fernet import Fernet  # type: ignore
import time
import os

# Set page config
st.set_page_config(
    page_title="Secure Vault",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if 'selected_menu' not in st.session_state:
    st.session_state.selected_menu = "Home"

if 'key' not in st.session_state:
    st.session_state.key = Fernet.generate_key()

cipher = Fernet(st.session_state.key)

# Passkey hashing
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Decrypt
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            cipher = Fernet(value["key"])
            try:
                return cipher.decrypt(encrypted_text.encode()).decode()
            except Exception as e:
                st.error(f"Decryption failed: {str(e)}")
                return None
    st.session_state.failed_attempts += 1
    return None

# App main logic
def main():
    with st.sidebar:
        st.title("🔐 Secure Vault")

        st.markdown("""
            <div style='background-color: rgba(255,255,255,0.1); padding: 10px; border-radius: 10px;'>
                <p style='color: black;'>Safeguard your private data with strong encryption and secure passkeys.</p>
            </div>
        """, unsafe_allow_html=True)

        menu = ["Home", "Encrypt & Store", "Decrypt & View", "Admin Login"]
        choice = st.radio("Select Menu", menu, index=0 if not st.session_state.failed_attempts >= 3 else 3)
        st.session_state.selected_menu = choice

    if choice == "Home":
        col1, col2 = st.columns([2, 1])
        with col1:
            st.title("🔐 Secure Encryption System")
            st.markdown(""" 
                <div style='background-color: rgba(30, 136, 229, 0.2); padding: 20px; border-radius: 10px;'>
                    <h3 style='color: #1e88e5;'>Your Encrypted Data Safe</h3>
                    <p>Encrypt confidential info with your custom passkey. Retrieve it only with the correct key.</p>
                    <p style='color: #ff9800;'>Nothing is saved permanently — it's completely private.</p>
                </div>
            """, unsafe_allow_html=True)
            st.markdown("### What You Can Do:")
            st.markdown(""" 
                - 🔏 Encrypt and store sensitive text.
                - 🔓 Decrypt using the same passkey.
                - 🚨 System locks after 3 incorrect attempts.
            """)
        with col2:
            st.image("security.png", width=200)
        st.markdown("---")
        st.info("Fernet symmetric encryption keeps your data secure and tamper-proof.")

    elif choice == "Encrypt & Store":
        st.title("🔏 Encrypt & Store Data")
        col1, col2 = st.columns([3, 1])
        with col1:
            user_data = st.text_area("Your Secret Information", height=150, placeholder="Type or paste data to encrypt...")
            passkey = st.text_input("Create a Secret Passkey", type="password", help="You'll need this to unlock the data later.")
            if st.button("Encrypt & Save", key="store_btn"):
                if user_data and passkey:
                    with st.spinner("Encrypting your data..."):
                        time.sleep(1)
                        hashed = hash_passkey(passkey)
                        encrypted = encrypt_data(user_data, passkey)
                        st.session_state.stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed, "key": st.session_state.key}
                        st.success("✅ Data encrypted and stored successfully!")
                        st.code(encrypted, language="text")
                        st.warning("Save this encrypted text and your passkey securely.")
                else:
                    st.error("⚠️ Both fields are required!")

    elif choice == "Decrypt & View" and not st.session_state.failed_attempts >= 3:
        st.title("🔓 Decrypt Your Data")
        encrypted_input = st.text_area("Encrypted Text", height=100, placeholder="Paste encrypted data here...")
        passkey_input = st.text_input("Enter Passkey", type="password")
        if st.button("Decrypt", key="retrieve_btn"):
            if encrypted_input and passkey_input:
                with st.spinner("Decrypting..."):
                    time.sleep(1)
                    decrypted = decrypt_data(encrypted_input, passkey_input)
                    if decrypted:
                        st.success("🔓 Decryption successful!")
                        st.text_area("Decrypted Output", value=decrypted, height=150)
                    else:
                        st.error(f"❌ Wrong passkey. Attempts remaining: {3 - st.session_state.failed_attempts}")
                        if st.session_state.failed_attempts >= 3:
                            st.warning("🚫 Too many failed attempts. Admin access required.")
                            st.session_state.authenticated = False
                            time.sleep(2)
                            st.experimental_rerun()
            else:
                st.error("⚠️ Please enter both encrypted text and passkey.")

    elif choice == "Admin Login" or st.session_state.failed_attempts >= 3:
        st.title("🔐 Admin Authentication Required")
        col1, col2 = st.columns([1, 2])
        with col1:
            st.image("https://cdn-icons-png.flaticon.com/512/3064/3064155.png", width=200)
        with col2:
            st.warning("You've hit the maximum failed attempts. Enter admin password to unlock.")
            admin_pass = st.text_input("Admin Password", type="password")
            if st.button("Authenticate", key="auth_btn"):
                if admin_pass == "secureVault123":  # In production, store this securely!
                    st.session_state.failed_attempts = 0
                    st.session_state.authenticated = True
                    st.success("✅ Admin authenticated. Access restored.")
                    time.sleep(1)
                    st.experimental_rerun()
                else:
                    st.error("❌ Incorrect admin password.")

    # Footer
    st.markdown("""
    <style>
    .footer {
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 20px;
        background-color: #333;
        color: white;
        font-size: 18px;
        font-weight: bold;
    }
    .linkedin-logo {
        width: 30px;
        height: 30px;
        margin-left: 10px;
        transition: all 0.3s ease;
    }
    .linkedin-logo:hover {
        transform: scale(1.2);
        filter: drop-shadow(0 0 10px #0077B5);
        animation: glow 1.5s infinite alternate;
    }
    @keyframes glow {
        from {
            filter: drop-shadow(0 0 5px #0077B5);
        }
        to {
            filter: drop-shadow(0 0 15px #0077B5);
        }
    }
    </style>
    <div class="footer">
        <span>Crafted with ❤️ by Kanwal Shahzadi</span>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
