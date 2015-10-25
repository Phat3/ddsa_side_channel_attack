# Active side channel attack against Deterministic DSA algorithm

## Introduction

With this work we want to introduce two active side channel attacks against the deterministic version of the Digital Signature Algorithm ( from now on DDSA ) as specified in the [RFC 6979](https://tools.ietf.org/html/rfc6979).
These attacks can lead directly to a leak of the private key and therefore breaking the authenticity of the signatures created using this algorithm.


## Dependencies

* [libgcrypt](https://www.gnu.org/software/libgcrypt/) 


## Instructions

1 - Download the latest version of libgcrypt

2 - Copy the file dsa.c inside libgcrypt/cipher/ ( overwrite the existing one )

3 - Compile the libgcrypt with:

	```bash
	cd $PATH_TO_LIBGCRYPY
	./configure --enable-maintainer-mode && make
	sudo make install
	```
4 - Go to the project root folder

5 - Compile the file that generates the various keypairs and generate them

	```bash
	gcc -o key_gen utils/dsa_key_generation.c `libgcrypt-config --cflags --libs`
	./key_gen
	```
6 - Compile the attack you want to test and run it

	```bash
	gcc -o attack attacks/attack1.c `libgcrypt-config --cflags --libs`
	./attack
	```
7 - Done! :)


## Attacks explanation

### Damage the exponentiation (attack1.c)

1 - Obtain the correct signature s = k^(-1)(m + x*r)		(1)

2 - Obtain the faulty signature s_tilde = k^(-1)(m + x*r_tilde)		(2)

3 - Write the system with the equation (1) and (2)

4 - Solving for x and k we can obtain the private key x

This attack runs with a time complexity of O(c).


### Damage the signature composition (attack2.c / attack2_byte.c)

For this attack we consider two level: a bit level and a byte level. In the first case the fault injected flips only one bit, while in the second case it flips at most 1 byte.

1 - Obtain the correct signature s = k^(-1)(m + x*r)	(1)

2 - Obtain the faulty signature s_tilde = k_tilde^(-1)(m + x*r)

3 - Express k_tilde as (k +/- 2^i)

4 - Compose the fraction s/s_tilde

5 - Solve the fraction for k and then retrive the private key x

We have to bruteforce all the possible value for i so the algorithm runs in O(n).


## More information

For a better and a complete explanation of these attacks see the pdf inside the repository.

