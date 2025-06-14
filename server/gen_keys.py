from Crypto.PublicKey import RSA
import os

def generate_keys(save_dir, prefix="client", bits=2048):
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    key = RSA.generate(bits)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()
    with open(os.path.join(save_dir, f"{prefix}_private.pem"), "wb") as f:
        f.write(private_pem)
    with open(os.path.join(save_dir, f"{prefix}_public.pem"), "wb") as f:
        f.write(public_pem)
    print("RSA密钥对生成成功！")

if __name__ == "__main__":
    generate_keys(save_dir="./keys", prefix="server")