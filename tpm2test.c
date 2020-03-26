/** @file tpm2test.c 			 */
/*                   			 */
/* @description main entry point */

#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdbool.h>

#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <tpm2-tss-engine.h>

#include "global.h"
#include "base64.h"

#define VERB(...) if (opt.verbose) fprintf(stderr, __VA_ARGS__)
#define ERR(...) fprintf(stderr, __VA_ARGS__)

static const char *optstr = "c:k:v";

static const struct option long_options[] = {
    {"csr filename", required_argument, 0, 'c'},
    {"keyfile",      required_argument, 0, 'k'},
    {"verbose",      no_argument,       0, 'v'},
    {0,              0,                 0,  0 }
};

static struct opt {
    char *          filename;   // The encrypted keypair file BLOB
    char *          csrfile;    // The csrfile location
    TPMI_ALG_PUBLIC alg;        // The algorithm to use (default:rsa)
    int             exponent;   // The exponent (default:65535)
    char *          ownerpw;    // The owner password (default:NULL)
    char *          password;   // The password (default:NULL)
    TPM2_HANDLE     parent;     // The parent ID, (default:0)
    char *          parentpw;   // The parent password (default:NULL)
    int             keysize;    // The keysize (default:2048)
    int             verbose;    // The verbose switch (default=off)
    char *          engine_id;  // The engine ID to use (default=tpm2tss)
} opt;

/** Parse and set command line options.
 *
 * This function parses the command line options and sets the appropriate values
 * in the opt struct.
 * @param argc The argument count.
 * @param argv The arguments.
 * @retval 0 on success
 * @retval 1 on failure
 */
int parse_opts(int argc, char **argv)
{
    /* parse the options */
    int c;
    int opt_idx = 0;
    while (-1 != (c = getopt_long(argc, argv, optstr,
                                  long_options, &opt_idx))) 
    {
        switch(c) 
        {
            case 'c':
                opt.csrfile = optarg;
                break;
            case 'k':
                opt.filename = optarg;
                break;
            case 'v':
                opt.verbose = 1;
                break;
            default:
                ERR("Unknown option at index %i.\n\n", opt_idx);
                exit( 1 );
        }
    }

    /* if there are any other arguments, they are unknown */
    if (optind < argc) 
    {
        ERR( "Unknown argument provided: %s.\n\n", optarg );
        exit( 1 );
    }
    return 0;
}

/** Generate an RSA key
 *
 * This function calls out to generate an RSA key using the TPM.
 * @param ENGINE *e a pointer to the engine to utilize
 * @retval TPM2_DATA data to be written to disk
 * @retval NULL on failure
 */
static TPM2_DATA *genkey_rsa( ENGINE *e )
{
    VERB("Generating RSA key using TPM\n");

    RSA *rsa = NULL;
    BIGNUM *exp = BN_new();
    if (!exp) 
    {
        ERR("out of memory\n");
        return NULL;
    }
    BN_set_word(exp, opt.exponent);

    rsa = RSA_new();
    if (!rsa) 
    {
        ERR("out of memory\n");
        BN_free(exp);
        return NULL;
    }
    if (!tpm2tss_rsa_genkey(rsa, opt.keysize, exp, opt.password, opt.parent)) 
    {
        BN_free(exp);
        RSA_free(rsa);
        ERR("Error: Generating key failed\n");
        return NULL;
    }

    VERB("Key generated...returning keypair to calling function\n");

    TPM2_DATA *tpm2Data = calloc(1, sizeof(*tpm2Data));
    if (tpm2Data == NULL) 
    {
        ERR("out of memory\n");
        BN_free(exp);
        RSA_free(rsa);
        return NULL;
    }
    /* export the data into an encrypted BLOB */
    memcpy(tpm2Data, RSA_get_app_data(rsa), sizeof(*tpm2Data));

    BN_free(exp);
    RSA_free(rsa);

    return tpm2Data;
} //genkey_rsa

/** generate & write key
 *
 * This function initializes OpenSSL and then calls the key generation
 * functions and writes the data to disk.
 * @param ENGINE *e = pointer to the engine to use
 * @retval TPM2_DATA * = pointer to the TPM2_DATA encrypted BLOB
 */
TPM2_DATA *tpm2tss_genkey( ENGINE *e )
{   
    TPM2_DATA *data = calloc(1, sizeof(*data));
    if (data == NULL) 
    {
        ERR("out of memory\n");
        return NULL;
    }

    VERB("Generating the key\n");
    switch ( opt.alg ) 
    {
        case TPM2_ALG_RSA:
            data = genkey_rsa( e );
            break;
        case TPM2_ALG_ECDSA:
            // TODO: Implement tpm2Data = genkey_ecdsa( e );
            // break;
        default:
            ERR("Engine algorithm selection error.\n");
            break;
    }

    if (data == NULL) 
    {
        ERR("Key could not be generated.\n");
        return NULL;
    }

    VERB("Writing key to disk\n");
    if ( !tpm2tss_tpm2data_write(data, opt.filename) ) 
    {
        ERR("Error writing file %s\n",opt.filename);
        free(data);
        return NULL;
    }

    VERB("*** SUCCESS ***\n");
    return data;
} //tpm2tss_genkey

/******************************************************************************/
/** @fn ENGINE* intitialize_engine( const char* engine_id )
    @brief Tries to initialize and open the engine passed to it.
    @brief It also sets the engine as the default engine for all functions
    @param engine_id The name of the engine to use e.g., default, tpm2tss
    @returns Pointer to the initialized engine ENGINE*
*/
/******************************************************************************/
ENGINE* initialize_engine( const char *engine_id )
{
    ENGINE *e = NULL;
    ENGINE_load_builtin_engines();

    // Set the engine pointer to an instance of the engine
    if ( !( e = ENGINE_by_id( engine_id ) ) )
    {
        ERR("Unable to find Engine: %s\n", engine_id);
        return NULL;
    }
    VERB("Found engine: %s", engine_id);

    // Initialize the engine for use
    if ( !ENGINE_init(e) )
    {
        ERR("Unable to initialize engine: %s\n", engine_id);
        return NULL;
    }
    VERB("Initialized engine: %s\n", engine_id);

    // Register the engine for use with all algorithms
    if ( !ENGINE_set_default( e, ENGINE_METHOD_ALL ) )
    {
        ERR("Unable to set %s as the default engine.", engine_id);
        return NULL;
    }
    VERB("Successfully set the default engine to %s.", engine_id);

    ENGINE_register_complete( e );
    return e;
} // initialize_engine

/******************************************************************************/
/** @fn char* generate_csr( EVP_PKEY* keyPair, X509_NAME* subject )
    @returns string of the signed CSR
*/
/******************************************************************************/
char* generate_csr( EVP_PKEY* keyPair, X509_NAME* subject )
{
    #undef FUNCTION
    #define FUNCTION "generate_csr"
    X509_REQ* req = NULL;
    unsigned char* reqBytes = NULL;
    char* csrString = NULL;
    if((req = X509_REQ_new()) && \
            X509_REQ_set_subject_name(req, subject) && \
            X509_REQ_set_pubkey(req, keyPair) && \
            X509_REQ_sign(req, keyPair, EVP_sha256()))  // ### RAL Changed has to 512 per Michael (from EVP_sha256())
    {
        int reqLen = i2d_X509_REQ(req, NULL);
        reqBytes = malloc(reqLen);
        unsigned char* tempReqBytes = reqBytes;
        i2d_X509_REQ(req, &tempReqBytes);

        csrString = base64_encode(reqBytes, (size_t)reqLen, false, NULL);
    }
    free(reqBytes);
    X509_REQ_free(req);
    return csrString;
} // generate_csr

static int read_subject_value(const char* subject, char* buf)
{
    int subjLen = strlen(subject);
    int subInd = 0;
    int bufInd = 0;

    bool done = false;
    bool hasError = false;

    while(!done && !hasError && subInd < subjLen)
    {
        char c = subject[subInd];
        switch(c)
        {
        case '\\':
            ;
            char escaped[1];
            unsigned int hexHi, hexLo;
            if(sscanf(&subject[subInd], "\\%1[\" #+,;<=>\\]", escaped) == 1)
            {
                if(buf)
                {
                    buf[bufInd++] = escaped[0];
                }
                subInd += 2;
            }
            else if(sscanf(&subject[subInd], "\\%1x%1x", &hexHi, &hexLo) == 2)
            {
                if(buf)
                {
                    buf[bufInd++] = (char)((hexHi << 4) | hexLo);
                }
                subInd += 3;
            }
            else
            {
                hasError = true;
            }
            break;
        case ',':
            done = true;
            break;
        default:
            if(buf)
            {
                buf[bufInd++] = c;
            }
            ++subInd;
            break;
        }
    }

    if(buf)
    {
        buf[bufInd] = '\0';
    }

    return hasError ? -1 : subInd;
} // read_subject_value

X509_NAME* parse_subject(const char* subject)
{
    X509_NAME* subjName = NULL;
    int subjLen = strlen(subject);
    int cur = 0;

    bool hasError = false;

    X509_NAME_ENTRY* rdnArr[20]; // 20 RDNs should be plenty
    int rdnCount = 0;

    while(!hasError && cur < subjLen)
    {
        int keyLen = strcspn(&subject[cur], "=");
        char keyBytes[keyLen+1];
        strncpy(keyBytes, &subject[cur], keyLen);
        keyBytes[keyLen] = '\0';
        cur += (keyLen + 1);

        if( cur < subjLen )
        {
            int valLen = read_subject_value(&subject[cur], NULL);
            if(valLen >= 0)
            {
                char valBytes[valLen+1];
                read_subject_value(&subject[cur], valBytes);
                cur += (valLen + 1);

                rdnArr[rdnCount] = X509_NAME_ENTRY_create_by_txt(NULL, keyBytes, MBSTRING_UTF8, (unsigned char*)valBytes, -1);
                rdnCount++;


                if(subject[cur-1] != '\0') // Don't try to advance if we just advanced past the null-terminator
                {
                    cur += strspn(&subject[cur], "\t\r\n "); // Whitespace between RDNs should be ignored
                }
            }
            else
            {
                ERR("Input string '%s' is not a valid X500 name", subject);
                hasError = true;
            }
        }
        else
        {
            ERR("Input string '%s' is not a valid X500 name", subject);
            hasError = true;
        }
    }

    if(!hasError)
    {
        subjName = X509_NAME_new();
        for(int rdnIndex = rdnCount - 1; rdnIndex >= 0; rdnIndex--)
        {
            X509_NAME_add_entry(subjName, rdnArr[rdnIndex], -1, 0);
        }
    }

    // Cleanup
    for(int rdnIndex = rdnCount - 1; rdnIndex >= 0; rdnIndex--)
    {
        X509_NAME_ENTRY_free(rdnArr[rdnIndex]);
    }

    return subjName;
} // parse_subject

/******************************************************************************/
/** @fn write_csr( const char* file, const char contents[], long len )
    @brief Writes a CSR to a file
    @param file = the filename to store the csr into
    @param contents[] = the CSR minus the header and footer
    @len the length of contents in bytes
    @retval 0 = success
    @retval !0 = failure
*/
/******************************************************************************/
int write_csr( const char* file, const char contents[], long len )
{
    int err = 0;
    int offset = 0;
    int loop;
    const char *header = "-----BEGIN CERTIFICATE REQUEST-----";
    const char *footer = "-----END CERTIFICATE REQUEST-----";

    remove( file );
    FILE* fp = fopen( file, "w" );
    if( !fp )
    {
        err = errno;
        char* errStr = strerror(errno);
        ERR("Unable to open file %s for writing: %s", file, errStr);
    }
    else
    {   
        /* write out header */
        err = fprintf( fp, "%s\n", header );
        if ( 0 == err )
        {
            ERR("Error writing header to file %s\n", file);
            fclose( fp );
            return err;
        }

        /* write out contents 64 chars at a time */
        loop = 0;
        while ( 64 > loop)
        {
            if ( contents[offset] != fputc( contents[offset], fp ) )
            {
                ERR("Error writing body to file %s\n", file);
                fclose( fp );
                return 1;
            }
            offset++;
            loop++;
            if ( len == offset )
            {
                fputc( '\n', fp );
                loop = 65;
            }
            if ( 64 == loop )
            {
                fputc( '\n', fp );
                loop = 0;
            }
        }

        /* write out footer */
        err = fprintf( fp, "%s\n", footer );
        if ( 0 == err )
        {
            ERR("Error writing footer to file %s\n", file);
            fclose( fp );
            return 1;
        }       
    }

    if(fp)
    {
        fclose(fp);
    }

    return 0;
} // write_csr

/**main function
 * @param argc The argument count.
 * @param argv The arguments.
 * @retval 0 on success
 * @retval 1 on failure
 **********************************************************************/
int main(int argc, char **argv) {

    /* set the default argument values */
    opt.filename =  NULL;
    opt.csrfile =   NULL;
    opt.alg =       TPM2_ALG_RSA;
    opt.exponent =  65537;
    opt.ownerpw =   NULL;
    opt.password =  NULL;
    opt.parent =    0;
    opt.parentpw =  NULL;
    opt.keysize =   2048;
    opt.verbose =   0;
    opt.engine_id = "tpm2tss";


    /*******************************************************************
     *  Parse the command line options
     ******************************************************************/
    if ( 0 != parse_opts( argc, argv ) ) 
    {
        exit( 1 );
    }

    /*******************************************************************
     *  1. Initialize the engine
     ******************************************************************/
    ENGINE *e = NULL;
    e = initialize_engine( opt.engine_id );
    if ( !e )
    {
        ERR( "Error initializing engine: %s\n", opt.engine_id );
        exit( 1 );
    }

    /*******************************************************************
     *  2. Generate a keypair using the TPM & write it to the disk
     ******************************************************************/
    TPM2_DATA *tpm2Data = calloc(1, sizeof(*tpm2Data));
    if ( NULL == tpm2Data ) 
    {
        ERR("out of memory\n");
        exit ( 1 );
    }
    tpm2Data = tpm2tss_genkey( e );
	if (  !e  ) 
    {
        ERR("Error generating key.\n");
        exit( 1 );
    }

    /*******************************************************************
     *  3. Clear out the tpm2Data to simulate launching the app with 
     *     a BLOB already on disk.
     ******************************************************************/
    if ( tpm2Data )
    {
        free( tpm2Data );
    }

    /*******************************************************************
     *  4. Load the data from the file system
     ******************************************************************/
    tpm2Data = calloc(1, sizeof(*tpm2Data));
    if (tpm2Data == NULL) 
    {
        ERR("out of memory\n");
        exit ( 1 );
    }
    if ( !tpm2tss_tpm2data_read( opt.filename, &tpm2Data ) )
    {
        ERR("Error reading back BLOB from %s\n", opt.filename );
        free( tpm2Data );
        exit ( 1 );
    }

    /*******************************************************************
     *  5. Generate an openSSL compatible RSA key
     ******************************************************************/
    EVP_PKEY *keyPair = NULL;
    keyPair = tpm2tss_rsa_makekey( tpm2Data ); // documentation wrong this is **
    if ( NULL == keyPair )
    {
        ERR("Error: tpm2tss_rsa_makekey\n");
        exit( 1 );
    }
    VERB("Successfully created openSSL compatible keyPair in memory.\n");

    /*******************************************************************
     *  6. Generate the signed CSR and save it to disk
     ******************************************************************/
    char *csr = generate_csr( keyPair, parse_subject("CN=Test Subject") );
    if ( NULL == csr )
    {
        ERR("Error generating csr!\n");
        exit( 1 );
    }
    VERB("CSR = %s\n", csr );
    VERB("Writing CSR to disk\n");

    if ( 0 != write_csr(opt.csrfile, csr, strlen(csr)) )
    {
        ERR( "Error writing csr to %s\n", opt.csrfile );
        free ( tpm2Data );
        free ( keyPair );
        exit( 1 );
    }
    VERB("Successfully wrote CSR to disk\n");

    /*******************************************************************
     *  7. Finalize and exit
     ******************************************************************/
    VERB("Finalizing....\n");
    if ( e )
    {
        ENGINE_finish( e );
        ENGINE_free( e );
    }
    if ( tpm2Data )
    {
        free( tpm2Data );
    }
    if ( keyPair )
    {
        free( keyPair );
    }
    VERB("Finalizing complete.\n");
    return 0;
} //main