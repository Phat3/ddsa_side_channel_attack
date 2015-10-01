/*
 * This program generates two DSA keys and
 * save them into file DSA_KEY
 *
 * */

#include <stdio.h>
#include <gcrypt.h>


int main(int argc , char* argv [])
{
	
	gcry_sexp_t dsa_key_pair , dsa_parms;
	
	gcry_sexp_t dsa_pub_key;
	
	gcry_sexp_t ciphertext , plaintext;
	
	gcry_error_t err;
	
	size_t dsa_key_size;
	
    err = gcry_sexp_build(&dsa_parms, NULL, "(genkey (dsa (nbits 4:1024)))" );  //the time to create keys increase exponentially with the key size ( min 1024 ) 
    
    //This function create a new public key pair using information given in the S-expression dsa_parms and stores the private and the public key in one new S-expression 
    //at the address given by dsa_key_pair
    err = gcry_pk_genkey(&dsa_key_pair, dsa_parms);
    
    puts("Key generated\n");
    
    dsa_key_size = sizeof(gcry_sexp_t);
    
    
	FILE* lockf = fopen("DSA_KEY", "wb");
		
				
	size_t buffer_size  = gcry_sexp_sprint(dsa_key_pair, GCRYSEXP_FMT_CANON, NULL, dsa_key_size);
	
	char buffer[buffer_size];
	gcry_sexp_sprint(dsa_key_pair, GCRYSEXP_FMT_CANON, buffer , buffer_size);
	
	if (fwrite(buffer, buffer_size, 1, lockf) != 1) {
        perror("fwrite");
        puts("fwrite() failed");
    }
    
    fclose(lockf);
		
}
