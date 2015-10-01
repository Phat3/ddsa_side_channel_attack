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
	gcry_sexp_t ciphertext , plaintext, ptx2;
	
	gcry_sexp_t r_param, r_tilda_param;
	gcry_sexp_t s_param, s_tilda_param;
	gcry_sexp_t g_param;
	gcry_sexp_t p_param;
	gcry_sexp_t q_param;
	
	gcry_error_t err;
	
	gcry_mpi_t msg_digest;
	
	
	gcry_mpi_t r , r_tilda;
	gcry_mpi_t s , s_tilda;
	gcry_mpi_t g;
	gcry_mpi_t p;
	gcry_mpi_t q;

    gcry_mpi_t s_delta = gcry_mpi_new(mpi_get_nbits(q));
    gcry_mpi_t numerator = gcry_mpi_new(mpi_get_nbits(q));

    gcry_mpi_t den_delta = gcry_mpi_new(mpi_get_nbits(q));
    gcry_mpi_t den_delta2 = gcry_mpi_new(mpi_get_nbits(q));
    gcry_mpi_t mg2i = gcry_mpi_new(mpi_get_nbits(q));
    gcry_mpi_t sg = gcry_mpi_new(mpi_get_nbits(q));
    gcry_mpi_t g2i = gcry_mpi_new(mpi_get_nbits(p));
    gcry_mpi_t denominator = gcry_mpi_new(mpi_get_nbits(q));
    gcry_mpi_t denominator_inv = gcry_mpi_new(mpi_get_nbits(q));

    gcry_mpi_t priv_guess = gcry_mpi_new(mpi_get_nbits(q));
    gcry_mpi_t k_inv_guess = gcry_mpi_new(mpi_get_nbits(q));

    gcry_mpi_t y = gcry_mpi_new(mpi_get_nbits(q));

    gcry_sexp_t new_dsa_key_pair;

    gcry_mpi_t s_new = gcry_mpi_new(mpi_get_nbits(q));
    gcry_sexp_t s_new_param;	
	
	
	int n = 1103 , i=0; // size of the file in which we have the dsa keys 
	
	
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

    //*************** CORRECT SIGNATURE ********************//

	//20 is the mdlen of sha1 as specified in https://lists.gnupg.org/pipermail/gnupg-devel/2013-September/027916.html
    //a well formatted number for the immaediate has an even number of digits
    err = gcry_sexp_build(&plaintext, NULL, "(data (flags rfc6979) (hash %s %b))" , "sha1", 20 , msg_digest);
	
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



    //*************** FAULTY SIGNATURE ********************//

    err = gcry_sexp_build(&ptx2, NULL, "(data (flags rfc6979) (hash %s %b) (attack))" , "sha1", 20 , msg_digest);

    err = gcry_pk_sign(&ciphertext, ptx2, dsa_key_pair);

    printf("OLD KEY PAIR\n");
    gcry_sexp_dump(dsa_key_pair);

    s_tilda_param = gcry_sexp_find_token(ciphertext, "s", 0);
    s_tilda = gcry_sexp_nth_mpi ( s_tilda_param , 1, GCRYMPI_FMT_USG);

    r_tilda_param = gcry_sexp_find_token(ciphertext, "r", 0);
    r_tilda = gcry_sexp_nth_mpi ( r_tilda_param , 1, GCRYMPI_FMT_USG);

    printf("R TILDA\n");
    gcry_mpi_dump(r_tilda);
    printf("\n");

    
    //NOW LET'S START THE ATTACK 

    unsigned long e = 0;

    int hash_len = 160;

    gcry_mpi_t one = gcry_mpi_set_ui(NULL, 1);

    //gcry_mpi_t minustwoi = gcry_mpi_new(e);
    
    for(e = 0; e < hash_len; e++){

        gcry_mpi_t twoi = gcry_mpi_new(e);
        gcry_mpi_mul_2exp(twoi, one, e);

    
    	//calculation for X
    	gcry_mpi_subm(s_delta, s, s_tilda, q);
    	gcry_mpi_mulm(numerator, msg_digest, s_delta, q);
    	gcry_mpi_powm(g2i, g, twoi, q);
    	gcry_mpi_mulm(sg, s, g2i, q);
        gcry_mpi_mulm(den_delta, s_tilda, r, q);
        gcry_mpi_mulm(den_delta2, sg, r_tilda, q);
    	gcry_mpi_subm(denominator, den_delta, den_delta2, q);
    	gcry_mpi_invm(denominator_inv, denominator, q);
    	gcry_mpi_mulm(priv_guess, numerator, denominator_inv, q);


    	//calculation for k^-1
    	//gcry_mpi_mulm(mg2i, msg_digest, g2i, mod);
    	//gcry_mpi_subm(denominator, msg_digest, mg2i, mod);
    	//gcry_mpi_invm(denominator_inv, denominator, mod);

    	//gcry_mpi_mulm(k_inv_guess, den_delta, denominator_inv, mod);

    	//calculate y
    	gcry_mpi_powm(y, g, priv_guess, p);

    	err = gcry_sexp_build(&new_dsa_key_pair,NULL,"(key-data ( public-key (dsa (p %m)(q %m)(g %m)(y %m))) (private-key (dsa (p %m)(q %m)(g %m)(y %m)(x %m))))", p,q,g,y,p,q,g,y,priv_guess);


    	err = gcry_pk_verify (ciphertext, plaintext, new_dsa_key_pair);

        if(e == 3){
            printf("NEW KEY PAIR\n");
            gcry_sexp_dump(new_dsa_key_pair);

            //gcry_mpi_release(p);
            //gcry_mpi_release(s);
            gcry_mpi_release(s_tilda);
            gcry_mpi_release(denominator);
            gcry_mpi_release(denominator_inv);
            gcry_mpi_release(den_delta);
             gcry_mpi_release(den_delta);
            //gcry_mpi_release(r_tilda);
        }
        
         if(e == 3){

             printf("NEW KEY PAIR\n");

             fflush(stdout);


            gcry_mpi_t g2iminus = gcry_mpi_new(mpi_get_nbits(p));
             
    
            gcry_mpi_powm(g2i, g, twoi, p);
            gcry_mpi_mod(s, g2i, q);

            //gcry_mpi_invm(g2iminus, g2i, q);


            gcry_mpi_mulm(g2iminus, r_tilda, s, p);
            gcry_mpi_mod(s, g2iminus, q);
            //gcry_mpi_mod(s, g2iminus, q);

            printf("RESULT\n");
            gcry_mpi_dump(s);
            printf("\n");
              

            return;
        }
        
    
        if (err) {
            puts("gcrypt: verify failed");
        }
        else{
            puts("BECCATO!!");
        }


    }

    printf("-----------------------------------------\n");
    printf("-----------------------------------------\n");
    printf("-----------------------------------------\n");

    gcry_mpi_t minus_one = gcry_mpi_set_ui(NULL, -1);

    for(e = 0; e < hash_len; e++){

        gcry_mpi_t twoi = gcry_mpi_new(e);
        gcry_mpi_mul_2exp(twoi, minus_one, e);

        //calculation for X
        gcry_mpi_subm(s_delta, s, s_tilda, q);
        gcry_mpi_mulm(numerator, msg_digest, s_delta, q);
        gcry_mpi_powm(g2i, g, twoi, q);
        gcry_mpi_mulm(sg, s, g2i, q);
        gcry_mpi_mulm(den_delta, s_tilda, r, q);
        gcry_mpi_mulm(den_delta2, sg, r_tilda, q);
        gcry_mpi_subm(denominator, den_delta, den_delta2, q);
        gcry_mpi_invm(denominator_inv, denominator, q);
        gcry_mpi_mulm(priv_guess, numerator, denominator_inv, q);


        //calculation for k^-1
        //gcry_mpi_mulm(mg2i, msg_digest, g2i, mod);
        //gcry_mpi_subm(denominator, msg_digest, mg2i, mod);
        //gcry_mpi_invm(denominator_inv, denominator, mod);

        //gcry_mpi_mulm(k_inv_guess, den_delta, denominator_inv, mod);

        //calculate y
        gcry_mpi_powm(y, g, priv_guess, p);

        err = gcry_sexp_build(&new_dsa_key_pair,NULL,"(key-data ( public-key (dsa (p %m)(q %m)(g %m)(y %m))) (private-key (dsa (p %m)(q %m)(g %m)(y %m)(x %m))))", p,q,g,y,p,q,g,y,priv_guess);

        err = gcry_pk_verify (ciphertext, plaintext, new_dsa_key_pair);
    
        if (err) {
            puts("gcrypt: verify failed");
        }
        else{
            puts("BECCATO!!");
        }


    }

}

