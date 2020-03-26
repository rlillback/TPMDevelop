Development code for TPM2 operations:

1.) Generate key on disk that is locked to the TPM  (tpm2tss-genkey -a rsa -s 2048 test.blob)
2.) Create csr using that key and the TPM engine (openssl req -new -engine tpm2tss -keyform engine -key test.blob -out test.csr)
3.) Check the csr using (openssl req -text -noout -verify -in test.csr)