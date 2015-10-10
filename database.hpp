#include <iostream>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <fstream>
#include <cstring>
#include <openssl/sha.h>
#include <vector>
#include <openssl/evp.h>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/vector.h>
#include <sstream>
#include <string>
#include <list>
#include <mysql/mysql.h>
#include <time.h>
#include "bn.h"
#include "test_point.hpp"


#define q 1000
#define AES_BLOCK_SIZE 128
#define INF 10000000
#define NINF -1
#define MAX_LEVEL 15
#define P 0.5


extern EVP_CIPHER_CTX en, de;
extern MYSQL *conn;

//public keys
extern std::vector<bn::Ec1> pubs_g1;//(q+1);
extern std::vector<bn::Ec2> pubs_g2;//(q+1);
extern std::vector<bn::Ec1> pubas_g1;//(q+1);
extern bn::Ec2 pubas_g2;



char* zToString(const NTL::ZZ_p &z);
NTL::ZZ_p StringToz(char* str);


//encryption
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx,EVP_CIPHER_CTX *d_ctx);
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);

//hash
bool simpleSHA256(void* input1, void* input2, unsigned long length1, unsigned long length2, unsigned char* md);

//bilinear

bn::Ec1 compute_digest_pub(std::vector<int> array, const bn::Ec1 g1);
bn::Ec1 compute_digest_pub_inverse(std::vector<int> array, const bn::Ec1 g1);
bn::Ec1 compute_digest_puba(std::vector<int> array, const bn::Ec1 g1);
bn::Ec1 compute_digest_puba_inverse(std::vector<int> array, const bn::Ec1 g1);
std::vector<int> intersection(std::vector<int> a, std::vector<int> b);
std::vector<int> difference(std::vector<int> a, std::vector<int> I);
void prove_intersection(std::vector<int>* I, bn::Ec1* digestI, bn::Ec1* w_extra,  std::vector<int> a, std::vector<int> b, bn::Ec2* w1, bn::Ec2* w2, bn::Ec1* Q1, bn::Ec1* Q2, bn::Ec1 g1, bn::Ec2 g2);
void prove_intersection_inverse(std::vector<int>* I, bn::Ec1* digestI, bn::Ec1* w_extra,  std::vector<int> a, std::vector<int> b, bn::Ec2* w1, bn::Ec2* w2, bn::Ec1* Q1, bn::Ec1* Q2, bn::Ec1 g1, bn::Ec2 g2);
bool verify_intersection(bn::Ec1 digestI, bn::Ec1 w_extra, bn::Ec1 a, bn::Ec1 b, bn::Ec2 w1, bn::Ec2 w2, bn::Ec1 Q1, bn::Ec1 Q2, bn::Ec1 g1, bn::Ec2 g2);

//random
float frand();
int random_level();

struct proofnode{
    int v;
    unsigned char f[32];
    int flag;
    
};

struct snode
{
    int value;
	int rowID;
    //int enc;
    NTL::ZZ_p enc2;
    unsigned char encry[255];
	bn::Ec1 g1_digest;
	bn::Ec2 g2_digest;
	unsigned char hash[SHA256_DIGEST_LENGTH];
    snode *right;
    snode *up;
    snode *down;
    snode *right0;
    snode(int value)
    {
        right = NULL;
        up = NULL;
        down = NULL;
        right0 = NULL;
        this->value = value;
        //enc = 1;
        
    }
};

struct skiplist
{
    snode *header;
    
    skiplist()
    {
        snode* temp;
        header = new snode(NINF);
        
        
        char buf[254];
        
        temp = header;
		header->rowID = NINF;
        header->enc2 = NTL::conv<NTL::ZZ_p>(1);
        {
            int len = 254;
            strcpy(buf,zToString(header->enc2));
            memcpy(temp->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
        }
        
        for(int i=0;i<MAX_LEVEL-1;i++){
            temp->down = new snode(NINF);
			temp->down->rowID = NINF;
            temp->down->enc2 = NTL::conv<NTL::ZZ_p>(1);
            int len = 254;
            memcpy(temp->down->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
            
            temp->down->up = temp;
            temp = temp->down;
        }
        {
            int len = 254;
            temp->right = new snode(INF);
			temp->right->rowID = INF;
            temp->right->enc2 = NTL::conv<NTL::ZZ_p>(1);
            memcpy(temp->right->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
			simpleSHA256(&temp->right->value, NULL, 4, 0, temp->right->hash);
        }
        
        temp->right0 = temp->right;
        
        
    }
    ~skiplist()
    {
        delete header;
    }
    void display();
    bool contains(int );
    void insert_element(int , int, NTL::ZZ_p , bn::Ec1, bn::Ec2);
	void insert_element_inorder(int , int, NTL::ZZ_p , bn::Ec1, bn::Ec2);
	void insert_element_inverse(int , int, NTL::ZZ_p , bn::Ec1, bn::Ec2);
	void insert_element_inverse_inorder(int , int, NTL::ZZ_p , bn::Ec1, bn::Ec2);
    void delete_element(int , bn::Ec1, bn::Ec2);
    std::vector<snode> range_search(int value_s, int value_e);
	std::vector<int> range_cover(snode* ancestor);
	std::vector<proofnode> prove_path(int );
};

//authenticated skiplist functions

void hash_from_path(std::vector<proofnode>, unsigned char*);

//database procedures
void single_d_query(std::string query, int start, int end, int col, std::vector<int> &result, std::vector<snode> &bi_digest, std::vector<bn::Ec1> &bi_proof, bn::Ec1 g1);
void single_d_query_inverse(int col2, std::string query, int start, int end, int col, std::vector<int> &result, std::vector<snode> &bi_digest, std::vector<bn::Ec1> &bi_proof, bn::Ec1 g1);
bool single_d_verify(std::vector<snode> bi_digest, std::vector<bn::Ec1> bi_proof, std::vector<int> result, bn::Ec1 g1, bn::Ec2 g2);
void multi_d_query(int dimension, std::vector<std::string> query, std::vector<int> start, std::vector<int> end, std::vector<int> col, std::vector<int> &result, std::vector<std::vector<snode> > &bi_digest, std::vector<std::vector<bn::Ec1> > &bi_proof, std::vector<bn::Ec1> &digestI, std::vector<bn::Ec1> &w_extra, std::vector<bn::Ec2> &w1, std::vector<bn::Ec2> &w2, std::vector<bn::Ec1> &Q1, std::vector<bn::Ec1> &Q2, bn::Ec1 g1, bn::Ec2 g2);
bool multi_d_verify(int dimension, std::vector<int> result, std::vector<std::vector<snode> > bi_digest, std::vector<std::vector<bn::Ec1> > bi_proof, std::vector<bn::Ec1> digestI, std::vector<bn::Ec1> w_extra, std::vector<bn::Ec2> w1, std::vector<bn::Ec2> w2, std::vector<bn::Ec1> Q1, std::vector<bn::Ec1> Q2, bn::Ec1 g1, bn::Ec2 g2);
void sum_single_d_query(std::string query, int start, int end, int col, int col2, int &result, std::vector<snode> &bi_digest, std::vector<bn::Ec1> &bi_proof, NTL::ZZ_p &c0, NTL::ZZ_p &c1, bn::Ec1 &c0_proof, bn::Ec1 &c1_proof, bn::Ec1 g1);
bool sum_single_d_verify(std::vector<snode> bi_digest, std::vector<bn::Ec1> bi_proof, int result, NTL::ZZ_p c0, NTL::ZZ_p c1, bn::Ec1 c0_proof, bn::Ec1 c1_proof, bn::Ec1 g1, bn::Ec2 g2);
void sum_multi_d_query(int dimension, std::vector<std::string> query, std::vector<int> start, std::vector<int> end, std::vector<int> col, int col2, int &result, std::vector<std::vector<snode> > &bi_digest, std::vector<std::vector<bn::Ec1> > &bi_proof, std::vector<bn::Ec1> &digestI, std::vector<bn::Ec1> &w_extra, std::vector<bn::Ec2> &w1, std::vector<bn::Ec2> &w2, std::vector<bn::Ec1> &Q1, std::vector<bn::Ec1> &Q2, NTL::ZZ_p &c0, NTL::ZZ_p &c1, bn::Ec1 &c0_proof, bn::Ec1 &c1_proof, bn::Ec1 g1, bn::Ec2 g2);
bool sum_multi_d_verify(int dimension, int result, std::vector<std::vector<snode> > bi_digest, std::vector<std::vector<bn::Ec1> > bi_proof, std::vector<bn::Ec1> digestI, std::vector<bn::Ec1> w_extra, std::vector<bn::Ec2> w1, std::vector<bn::Ec2> w2, std::vector<bn::Ec1> Q1, std::vector<bn::Ec1> Q2, NTL::ZZ_p c0, NTL::ZZ_p c1, bn::Ec1 c0_proof, bn::Ec1 c1_proof, bn::Ec1 g1, bn::Ec2 g2);
int maxmin(std::string query);

//database global
extern std::vector<std::vector<skiplist> > ss;
extern std::vector<std::vector<std::vector<skiplist> > > ss_sum;

