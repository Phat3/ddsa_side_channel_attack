/*
 * This program generates two DSA keys and
 * save them into file DSA_KEY
 *
 * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>

 void keygen(int option){

 	gcry_sexp_t dsa_key_pair , dsa_parms;
	
	gcry_sexp_t dsa_pub_key;
	
	gcry_sexp_t ciphertext , plaintext;
	
	gcry_error_t err;
	
	size_t dsa_key_size;

	char * filename;

	switch(option)
	{
		//generate the 1024/160 bits key pair
		case (1):
			err = gcry_sexp_build(&dsa_parms, NULL, "(genkey (dsa (nbits 4:1024)))"); 
			filename = "DSA_KEY_1024"; 
			break;
		//generate the 2048/224 bits key pair
		case (2):
			err = gcry_sexp_build(&dsa_parms, NULL, "(genkey (dsa (nbits 4:2048)))"); 
			filename = "DSA_KEY_2048_224";  
			break;
		//generate the 2048/256 bits key pair
		case (3):
			err = gcry_sexp_build(&dsa_parms, NULL, "(genkey (dsa (nbits 4:2048) (qbits 3:256)))");  
			filename = "DSA_KEY_2048_256"; 
			break;

		case (4):
			err = gcry_sexp_build(&dsa_parms, NULL, "(genkey (dsa (nbits 4:3072) (qbits 3:256)))");  
			filename = "DSA_KEY_3072_256"; 
			break;

		default:	
			printf("Invalid option");
			exit(0);
	}		
    
    //This function create a new public key pair using information given in the S-expression dsa_parms and stores the private and the public key in one new S-expression 
    //at the address given by dsa_key_pair
    err = gcry_pk_genkey(&dsa_key_pair, dsa_parms);

    
    dsa_key_size = sizeof(gcry_sexp_t);
    
    
	FILE* lockf = fopen(filename, "wb");
		
				
	size_t buffer_size  = gcry_sexp_sprint(dsa_key_pair, GCRYSEXP_FMT_CANON, NULL, dsa_key_size);
	
	char buffer[buffer_size];
	gcry_sexp_sprint(dsa_key_pair, GCRYSEXP_FMT_CANON, buffer , buffer_size);
	
	if (fwrite(buffer, buffer_size, 1, lockf) != 1) {
        perror("fwrite");
        puts("fwrite() failed");
    }
    
    fclose(lockf);
 }


int main(int argc , char* argv [])
{
	printf("Start generating the keys...\n");

	printf("Generating the 1024/160 bits key pair\n");
	keygen(1);

	printf("Generating the 2048/224 bits key pair\n");
	keygen(2);

	printf("Generating the 2048/256 bits key pair\n");
	keygen(3);

	printf("Generating the 3072/256 bits key pair\n");
	keygen(4);

	printf("SUCCESS!!\n");
	
}
