from saga.config import CA_CONFIG, PROVIDER_CONFIG
from saga.common.crypto import generate_ca, save_ca


def main(config, file_path):
    # Generate credentials
    pri_key, pub_key, cert = generate_ca(config)
    # Save these credentials to files
    save_ca(file_path, config.get("ORG_NAME"), pri_key, pub_key, cert)


if __name__ == "__main__":
    import sys
    who = sys.argv[1]
    if who not in ["ca", "provider"]:
        raise ValueError("Invalid argument. Use 'ca' or 'provider'.")
    save_path = sys.argv[2]

    if who == "ca":
        config = CA_CONFIG.get("config")
    else:
        config = PROVIDER_CONFIG.get("config")

    main(config, save_path)
