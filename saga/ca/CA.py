import os
import saga.common.crypto as sc
import saga.config
import requests
from saga.common.logger import Logger as logger


def download_file(url, save_path):
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(save_path, 'wb') as file:
            for chunk in response.iter_content(1024):
                file.write(chunk)
        logger.log("CA", f"File downloaded: {save_path}")
    else:
        raise ValueError(f"Failed to download file from {url}  Status code: {response.status_code}")


class CA:
    """
    A class to represent a Certificate Authority (CA).
    This class is responsible for managing the CA's private key, public key, and certificate.
    It can sign public keys to generate X.509 certificates and verify existing certificates.
    It downloads the necessary files from a specified endpoint and initializes the CA with them.
    """
    def __init__(self, workdir, config):
        """
        Initializes the CA with the given working directory and configuration.

        Args:
            workdir: The directory where the CA's keys and certificate will be stored.
            config: A dictionary containing configuration parameters for the CA.
        """
        self.orgname = config.get("config").get("ORG_NAME", "CA")
        self.workdir = workdir
        if self.workdir[-1] != '/':
            self.workdir += '/'
        
        if not os.path.exists(self.workdir):
            os.mkdir(self.workdir)
        
        # Download relevant files from endpoint into current directory
        endpoint = saga.config.CA_CONFIG.get('endpoint')
        if endpoint is None:
            raise ValueError("CA endpoint is None - please specify endpoint for CA in config.yaml")
        
        # Download files from endpoint
        logger.log("CA", f"Downloading files from CA endpoint: {endpoint}")
        for file in ["key", "pub", "crt"]:
            url = f"{endpoint}/{self.orgname}.{file}"
            save_path = os.path.join(self.workdir, f"{self.orgname}.{file}")
            download_file(url, save_path)
        
        # Load the keys and certificate of the CA, since they exist:
        self.private_key, self.public_key, self.cert = sc.load_ca(self.workdir, self.orgname)

    def sign(self, public_key, config):
        """
        Generates a signed X.509 certificate.

        Args:
            public_key: The public key to be signed.
            config: A dictionary containing certificate information (e.g., COUNTRY_NAME).
        """
        return sc.generate_x509_certificate(
            config, 
            public_key,
            ca_private_key=self.private_key,
            ca_certificate=self.cert
        )

    def verify(self, certificate):
        """
        Verifies a X.509 certificate.

        Args:
            certificate: The X.509 certificate to verify.
        """
        sc.verify_x509_certificate(
            certificate=certificate, 
            ca_certificate=self.cert
        )

def get_SAGA_CA():
    """
    Returns an instance of the CA class initialized with the SAGA configuration.
    """
    return CA(
        workdir=saga.config.CA_WORKDIR,
        config=saga.config.CA_CONFIG
    )
