#include <stdio.h>
#include <string.h>
#include <gcrypt.h>

#define DEBUG_MPI_PRINT(mpi,msg) { printf("%s\n", msg); gcry_mpi_dump(mpi); printf("\n"); }

#define DEBUG_SEXP_PRINT(sexp,msg) { printf("%s\n", msg); gcry_sexp_dump(sexp); printf("\n"); }

//get the size of the key file
int get_file_size(FILE * fp){
    fseek(fp, 0L, SEEK_END);
    int size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    return size;
}

//DEBUG
void print_hash(unsigned char* digest, int hash_len){
    //the hex representation has twice the length of the binary representation
    char *out = (char *) malloc( sizeof(char) * ((hash_len*2)+1) ); 
    char *pointer = out;
    int j;
    for ( j = 0; j < hash_len; j++, pointer += 2 ) {
        snprintf ( pointer, 3, "%02x", digest[j] );
    }

    printf( "HEX REP: %s\n", out );
    free( out );
}

/*
 * This is an implementation of the 
 * ddsa algorithm as specified in rfc6979 
 * 
 * */
int main( int argc , char * argv[]){
	

    void* dsa_buf; 
    
    gcry_sexp_t dsa_key_pair;
    gcry_sexp_t dsa_pub_key;
    gcry_sexp_t ciphertext , plaintext, ptx2, ctx2;
    
    gcry_sexp_t r_param, r_tilda_param, k_tilda_param, x_param;
    gcry_sexp_t s_param, s_tilda_param;
    gcry_sexp_t g_param;
    gcry_sexp_t p_param;
    gcry_sexp_t q_param;
    
    gcry_error_t err;
    
    gcry_mpi_t msg_digest;
    
    
    gcry_mpi_t r , x, r_tilda, k_tilda;
    gcry_mpi_t s , s_tilda;
    gcry_mpi_t g;
    gcry_mpi_t p;
    gcry_mpi_t q;

    int i=0;
    
    /* Let's retreive the key from the file */
    //----------------------------------------
    
    FILE* lockf = fopen("DSA_KEY_2048_256", "rb");

    int n = get_file_size(lockf); // size of the file in which we have the dsa keys 

    
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

    
   //----------------------------------------
    
    //*************** HASH THE MASSAGE ********************//

    const unsigned char* message = (const unsigned char * ) "Hello world.";

    //get the hash_len of sha-1
    int hash_len = gcry_md_get_algo_dlen(GCRY_MD_SHA1);

    unsigned char digest[hash_len];

    //calculate the hash in the binary representation
    //the gcry_sexp_build requires the binary representation of the hash (20 bytes long)
    //the ascii and the hex representations are 40 bytes long and this broke the HMAC computation when you try to sign your message 
    gcry_md_hash_buffer(GCRY_MD_SHA1, digest, message, strlen(message));

    //DEBUG --IT WORKS--
    print_hash(digest,hash_len);

    //*************** CORRECT SIGNATURE ********************//

    //20 is the mdlen of sha1 as specified in https://lists.gnupg.org/pipermail/gnupg-devel/2013-September/027916.html
    err = gcry_sexp_build(&plaintext, NULL, "(data (flags rfc6979) (hash %s %b))" , "sha1", hash_len , digest);
    
    err = gcry_pk_sign(&ciphertext, plaintext, dsa_key_pair);

    x_param = gcry_sexp_find_token(dsa_key_pair, "x", 0);
    x = gcry_sexp_nth_mpi ( x_param , 1, GCRYMPI_FMT_USG);

    printf("X\n");
    gcry_mpi_dump(x);
    printf("\n");

    x_param = gcry_sexp_find_token(plaintext, "hash", 0);
    x = gcry_sexp_nth_mpi ( x_param , 2, GCRYMPI_FMT_USG);

    printf("DIGEST\n");
    gcry_mpi_dump(x);
    printf("\n");



    //now let's convert the s-expression representing r into an MPI in order
    //to use it in the equation of the attack 

    //--------- CIPHERTEXT --------------
    
    r_param = gcry_sexp_find_token(ciphertext, "r", 0);
    r = gcry_sexp_nth_mpi ( r_param , 1, GCRYMPI_FMT_USG);
         
    s_param = gcry_sexp_find_token(ciphertext, "s", 0);
    s = gcry_sexp_nth_mpi ( s_param , 1, GCRYMPI_FMT_USG);

    //--------- PUB KEY --------------
    
    g_param = gcry_sexp_find_token(dsa_key_pair, "g", 0);
    g = gcry_sexp_nth_mpi ( g_param , 1, GCRYMPI_FMT_USG);
    
    p_param = gcry_sexp_find_token(dsa_key_pair, "p", 0);
    p = gcry_sexp_nth_mpi ( p_param , 1, GCRYMPI_FMT_USG);
    
    q_param = gcry_sexp_find_token(dsa_key_pair, "q", 0);
    q = gcry_sexp_nth_mpi ( q_param , 1, GCRYMPI_FMT_USG);

    DEBUG_MPI_PRINT(g,"g");

    DEBUG_MPI_PRINT(p,"p");

    DEBUG_MPI_PRINT(q,"q");

    DEBUG_MPI_PRINT(r,"r");

    
    //*************** FAULTY SIGNATURE ********************//

    err = gcry_sexp_build(&ptx2, NULL, "(data (flags rfc6979) (hash %s %b) (attack2))" , "sha1", 20 , digest);

    err = gcry_pk_sign(&ctx2, ptx2, dsa_key_pair);

    s_tilda_param = gcry_sexp_find_token(ctx2, "s", 0);
    s_tilda = gcry_sexp_nth_mpi ( s_tilda_param , 1, GCRYMPI_FMT_USG);

    r_tilda_param = gcry_sexp_find_token(ctx2, "r", 0);
    r_tilda = gcry_sexp_nth_mpi ( r_tilda_param , 1, GCRYMPI_FMT_USG);

    k_tilda_param = gcry_sexp_find_token(ctx2, "k", 0);
    k_tilda = gcry_sexp_nth_mpi ( k_tilda_param , 1, GCRYMPI_FMT_USG);

    DEBUG_MPI_PRINT(r_tilda,"R_tilda");

    DEBUG_MPI_PRINT(k_tilda,"K-tilda");

    printf("K\n");
    gcry_mpi_t eight = mpi_set_ui(NULL, 8);
    gcry_mpi_add(k_tilda, k_tilda, eight);
    gcry_mpi_dump(k_tilda);
    printf("\n");

    gcry_mpi_t one = mpi_set_ui(NULL, 1);

    gcry_mpi_t e = mpi_new(4);
    mpi_mul_2exp(e, one, 3);   // e = 2^i ---> in this example e = 2^3

    gcry_mpi_t result = gcry_mpi_new(mpi_get_nbits(s));

    gcry_mpi_t s_tilda2 = gcry_mpi_new(mpi_get_nbits(q));

    //POC

    //retrieve k
    gcry_mpi_mulm(s_tilda2, s_tilda, e, q); // s_tilda*(2^3) mod q
    gcry_mpi_subm(s_tilda2, s_tilda2, q, q); // q - s_tilda*(2^3)  mod q   ------>  this is equivalent to -s_tilda(2^3) mod q
    gcry_mpi_subm(result, s_tilda, s, q); // s_tilda - s mod q
    gcry_mpi_invm(result, result, q); // (s_tilda - s mod q)^-1
    gcry_mpi_mulm(result,result, s_tilda2, q); // (q) - s_tilda*(2^3)  mod q)*(s_tilda - s mod q)^-1 === k

    printf("K RECONSTRUCTED\n");
    gcry_mpi_dump(result);
    printf("\n");

    //retrieve x
    gcry_mpi_mulm(result, s, result,q); // s*k mod q
    gcry_mpi_subm(result, result, x, q); // s*k - m mod q
    gcry_mpi_invm(r,r,q); // r^-1
    gcry_mpi_mulm(result, result,r,q); //(s*k -m)*r^-1 mod q

    printf("X RECONSTRUCTED\n");
    gcry_mpi_dump(result);   //WORKING!!
    printf("\n");

}

