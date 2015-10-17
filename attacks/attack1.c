#include <stdio.h>
#include <gcrypt.h>


#define DEBUG_MPI_PRINT(mpi,msg) { printf("%s", msg); fflush(stdout); gcry_mpi_dump(mpi);}

#define DEBUG_SEXP_PRINT(sexp,msg) { printf("%s\n", msg); gcry_sexp_dump(sexp); printf("\n"); }


//---------------------- GLOBAL VARIABLES ----------------------

//create the s-expressions for the key
gcry_sexp_t dsa_key_pair;
//name of the files in which the different keypairs are stored
char * files[] = {"DSA_KEY_1024", "DSA_KEY_2048_224", "DSA_KEY_2048_256", "DSA_KEY_3072_256"};


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
    
        gcry_error_t err;

        gcry_sexp_t ciphertext , plaintext, ptx2;
        
        gcry_sexp_t r_param, r_tilda_param, k_tilda_param, msg_digest_param;
        gcry_sexp_t s_param, s_tilda_param;
        gcry_sexp_t g_param;
        gcry_sexp_t p_param;
        gcry_sexp_t q_param;
        gcry_sexp_t x_param;
        
        
        
        gcry_mpi_t r , r_tilda, k_tilda, x;
        gcry_mpi_t s , s_tilda;
        gcry_mpi_t g;
        gcry_mpi_t p;
        gcry_mpi_t q;
        gcry_mpi_t msg_digest;
   

        retrieve_key_pair(files[i]);

        //*************** CORRECT SIGNATURE ********************//

        //20 is the mdlen of sha1 as specified in https://lists.gnupg.org/pipermail/gnupg-devel/2013-September/027916.html
        //a well formatted number for the immaediate has an even number of digits
        err = gcry_sexp_build(&plaintext, NULL, "(data (flags rfc6979) (hash %s %b))" , "sha1", hash_len , digest);

        err = gcry_pk_sign(&ciphertext, plaintext, dsa_key_pair);


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

        x_param = gcry_sexp_find_token(dsa_key_pair, "x", 0);
        x = gcry_sexp_nth_mpi ( x_param , 1, GCRYMPI_FMT_USG);

	unsigned int qbits = mpi_get_nbits(q);
	unsigned int pbits = mpi_get_nbits(p);
    

        msg_digest_param = gcry_sexp_find_token(plaintext, "hash", 0);
        msg_digest = gcry_sexp_nth_mpi ( msg_digest_param , 2, GCRYMPI_FMT_USG);



        //*************** FAULTY SIGNATURE ********************//

        err = gcry_sexp_build(&ptx2, NULL, "(data (flags rfc6979) (hash %s %b) (attack))" , "sha1", hash_len , digest);

        err = gcry_pk_sign(&ciphertext, ptx2, dsa_key_pair);

        s_tilda_param = gcry_sexp_find_token(ciphertext, "s", 0);
        s_tilda = gcry_sexp_nth_mpi ( s_tilda_param , 1, GCRYMPI_FMT_USG);

        r_tilda_param = gcry_sexp_find_token(ciphertext, "r", 0);
        r_tilda = gcry_sexp_nth_mpi ( r_tilda_param , 1, GCRYMPI_FMT_USG);

        k_tilda_param = gcry_sexp_find_token(ciphertext, "k", 0);
        k_tilda = gcry_sexp_nth_mpi ( k_tilda_param , 1, GCRYMPI_FMT_USG);


        //POC 

        // 1 - choose a message
        // 2 - do the correct sign and obtain s and r
        // 3 - do the faulty sign and obtain s_tilda and r_tilda

        gcry_mpi_t tmp = gcry_mpi_new(mpi_get_nbits(p));

        gcry_mpi_t result = gcry_mpi_new(mpi_get_nbits(p));

        gcry_mpi_subm(tmp, s_tilda, s,q);   //s-tilda -s mod q

        gcry_mpi_mulm(msg_digest, msg_digest, tmp, q);  //m* (s-tilda -s mod q) mod q

        gcry_mpi_mulm(tmp, r_tilda, s, q);  //r_tilda - s mod q

        gcry_mpi_mulm(result, s_tilda, r, q);    //s_tilda - r mod q

        gcry_mpi_subm(result, tmp, result, q);  //(r_tilda - s mod q) - (s_tilda - r mod q) mod q

        gcry_mpi_invm(result,result,q); //((r_tilda - s mod q) - (s_tilda - r mod q) mod q)^-1 mod q

        gcry_mpi_mulm(result, msg_digest, result, q);   //( (m* (s-tilda -s mod q) mod q) * ((r_tilda - s mod q) - (s_tilda - r mod q) mod q)^-1 mod q ) mod q == x (private key)

        printf("\n[!!!]PRIVATE KEY %d %d BITS CRACKED!!\n" , pbits,qbits );
    	     
	DEBUG_MPI_PRINT(result,"X = ");
	printf("\n");
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

    puts("\n");

    for(i = 0; i<4; i++){

	printf("******** ATTACKING %s ******* \n" , files[i]);
        attack(i,digest,hash_len);
	printf("PRIVATE KEY CRACKED\n ");
 	printf("\n\n");
    
    }

}

