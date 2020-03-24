Development code for TPM2 operations:

1.) Generate key on disk that is locked to the TPM  (tpm2tss-genkey -a rsa -s 2048 pub_priv_blob.key)
2.) Create self signed csr using that key and the TPM engine (openssl req -new -x509 -engine tpm2tss -keyform engine -key pub_priv_blob.key -out client.csr)