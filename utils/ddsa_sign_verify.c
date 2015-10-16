#include <stdio.h>
#include <gcrypt.h>

/*
 * This is an implementation of the 
 * ddsa algorithm as specified in rfc6979 
 * 
 * */
int main( int argc , char * argv[]){

	void* dsa_buf; 
	
	gcry_sexp_t dsa_key_pair;
	gcry_sexp_t dsa_pub_key;
	gcry_sexp_t ciphertext , plaintext;
	
	gcry_error_t err;
	
	gcry_mpi_t msg_digest;
	
	int n = 1103; // size of the file in which we have the dsa keys 
	
	
	/* Let's retreive the key from the file */
	//----------------------------------------
	
	FILE* lockf = fopen("DSA_KEY", "rb");
    
    if (!lockf) {
        puts("fopen() failed");
    }
	
	dsa_buf = malloc(n);
    if (!dsa_buf) {
        puts("malloc: could not allocate rsa buffer");
    }
	
	if (fread(dsa_buf, n, 1, lockf) != 1) {
       puts("fread() failed");
    }
	
    err = gcry_sexp_new(&dsa_key_pair, dsa_buf, n, 0);
    
    if(err){
		puts("Error");
		}


    //gcry_sexp_dump(dsa_key_pair);
    
   //----------------------------------------
    
   //digest of "Hello world." 
    const unsigned char* digest = (const unsigned char * ) "e44f3364019d18a151cab7072b5a40bb5b3e274f";
    
    err = gcry_mpi_scan(&msg_digest, GCRYMPI_FMT_USG, digest, 
                        strlen((const char*) digest), NULL);
    
    //20 is the mdlen of sha1 as specified in https://lists.gnupg.org/pipermail/gnupg-devel/2013-September/027916.html
    err = gcry_sexp_build(&plaintext, NULL, "(data (flags rfc6979) (hash %s %b))" , "sha1", 20 , msg_digest);
    
	if(err){
		puts("Error in build");
        fprintf (stderr, "Failure: %s/%s\n",
                  gcry_strsource (err),
                  gcry_strerror (err));	
		}
    
    /*
    puts("The plaintext was:\n");
	gcry_sexp_dump(plaintext);
	*/
	
	err = gcry_pk_sign(&ciphertext, plaintext, dsa_key_pair);
	
	if(err){
		puts("Error in sign");
        fprintf (stderr, "Failure: %s/%s\n",
                  gcry_strsource (err),
                  gcry_strerror (err));	
		}

	puts("The ciphertext is:\n");
	
	gcry_sexp_dump(ciphertext);
	
	puts("Verifing\n");

	err = gcry_pk_verify (ciphertext, plaintext, dsa_key_pair);

	if (err) {
        puts("gcrypt: verify failed");
    }
    else
        puts("Verifing OK!");
    
}
