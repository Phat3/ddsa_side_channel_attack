#include <stdio.h>
#include <gcrypt.h>

/*
 * -----TUTORIAL-------------------------------------------
 * http://wiki.ucalgary.ca/images/8/8f/Wk6.Session2.pdf
 * https://github.com/vedantk/gcrypt-example
 * https://github.com/vedantk/gcrypt-example/blob/master/main.cc#L43
 * --------------------------------------------------------
 * 
 * https://www.gnupg.org/documentation/manuals/gcrypt/Used-S_002dexpressions.html#Used-S_002dexpressions
 * https://www.gnupg.org/documentation/manuals/gcrypt/DSA-key-parameters.html#DSA-key-parameters
 * http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
 * https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Prime_number_generation
 * 
*/

/*
 * -----COMPILATION----------------------------------------
 * gcc -o crypto crypto.c `libgcrypt-config --cflags --libs` 
 * --------------------------------------------------------
 * 
 * */
/*
 * S-EXPRESSIONS ( basically the list in Scheme! ) 
 * 
 * http://people.csail.mit.edu/rivest/Sexp.txt
 * S-expressions are data structures for representing complex data
 * 
 * A DSA private key is described by this S-expression:
 * (private-key
    (dsa
	  (p p-mpi)  -> prime number p 
      (q q-mpi)  -> prime number q 
      (g g-mpi)  -> generator of the group g 
      (y y-mpi)  -> public key value g^s 
      (x x-mpi)  -> secret exponent s 
     ))
 *
 * ID-PK-ALGO
 * gcry_pk_algo_name(17) -- > DSA 
 * ----------
 * ID | Name
 * ----------
 * 1  |  RSA  
 * 16 |  ELG
 * 17 |  DSA
 * ----------
 * 
 * */
int main( int argc , char * argv[]){
	
	gcry_sexp_t dsa_key_pair , dsa_parms;
	

	
	gcry_sexp_t dsa_pub_key;
	
	gcry_sexp_t ciphertext , plaintext;
	
	gcry_error_t err;
	
	int n = 1103;
	
	
	FILE* lockf = fopen("DSA_KEY", "rb");
    
    if (!lockf) {
        puts("fopen() failed");
    }
	
	void* dsa_buf = malloc(n);
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
    //gcry_sexp_t pubk = gcry_sexp_find_token(dsa_keypair, "public-key", 0);
    //gcry_sexp_t privk = gcry_sexp_find_token(dsa_keypair, "private-key", 0);
    gcry_sexp_dump(dsa_key_pair);
    
    
    gcry_mpi_t msg;
    
    const unsigned char* s = (const unsigned char*) "Hello world.";
    
    err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, s, 
                        strlen((const char*) s), NULL);
    
    err = gcry_sexp_build(&plaintext, NULL, "(data (flags raw) (value %m))", msg);
    
    
    puts("The plaintext was:\n");
	gcry_sexp_dump(plaintext);
	
	err = gcry_pk_sign(&ciphertext, plaintext, dsa_key_pair);

	puts("The ciphertext is:\n");
	
	gcry_sexp_dump(ciphertext);
	
	puts("Verifing\n");
	
	err = gcry_pk_verify (ciphertext, plaintext, dsa_key_pair);
	
	
	if (err) {
        puts("gcrypt: verify failed");
    }
     
}
