#include "database.hpp"


using namespace std;
using namespace NTL;
using namespace bn;






char* zToString(const ZZ_p &z) {
    std::stringstream buffer;
    buffer << z;
	
    char *zzstring = strdup(buffer.str().c_str());
    return zzstring;
}


ZZ_p StringToz(char* str){
    ZZ temp=conv<ZZ>(str);
    return conv<ZZ_p>(temp);
}

//database verify
bool single_d_verify(vector<snode> bi_digest, vector<Ec1> bi_proof, vector<int> result, Ec1 g1, Ec2 g2){
	{
		Fp12 e1,e2;
		opt_atePairing(e1, bi_digest[1].g2_digest, bi_digest[0].g1_digest);
		opt_atePairing(e2, g2, bi_proof[0]);
		if(e1 != e2){
			cout<<"fail 0\n";
			return false;
		}
	}
	
	for(int i=0;i<bi_proof.size()-1;i++){
		Fp12 e1,e2;
		opt_atePairing(e1, bi_digest[i+2].g2_digest, bi_proof[i]);
		opt_atePairing(e2, g2, bi_proof[i+1]);
		if(e1 != e2){
			cout<<"fail "<<i+1<<"\n";
			return false;
		}
	}
	
	if(compute_digest_pub(result,g1) != bi_proof[bi_proof.size()-1]){
		cout<<"fail last\n";
		return false;
	}
	
	return true;
}


bool multi_d_verify(int dimension, vector<int> result, vector<vector<snode> > bi_digest, vector<vector<Ec1> > bi_proof, vector<Ec1> digestI, vector<Ec1> w_extra, vector<Ec2> w1, vector<Ec2> w2, vector<Ec1> Q1, vector<Ec1> Q2, Ec1 g1, Ec2 g2){
	
	//verify union
	for(int d = 0; d < dimension; d++){
		{
			Fp12 e1,e2;
			opt_atePairing(e1, bi_digest[d][1].g2_digest, bi_digest[d][0].g1_digest);
			opt_atePairing(e2, g2, bi_proof[d][0]);
			if(e1 != e2){
				cout<<"fail 0\n";
				return false;
			}
		}
		
		for(int i=0;i<bi_proof[d].size()-1;i++){
			Fp12 e1,e2;
			opt_atePairing(e1, bi_digest[d][i+2].g2_digest, bi_proof[d][i]);
			opt_atePairing(e2, g2, bi_proof[d][i+1]);
			if(e1 != e2){
				cout<<"fail "<<i+1<<"\n";
				return false;
			}
		}
	}
	
	//test
	if(result.size() == 0){
		return true;
	}
	
	//verify intersection
	
	if(!verify_intersection(digestI[0], w_extra[0], bi_proof[0][bi_proof[0].size()-1], bi_proof[1][bi_proof[1].size()-1], w1[0],w2[0],Q1[0],Q2[0],g1,g2)){
		cout<<"fail dimension 0\n";
		return false;
	}

	for(int d=1; d<dimension-1;d++){
		if(!verify_intersection(digestI[d], w_extra[d], digestI[d-1], bi_proof[d+1][bi_proof[d+1].size()-1], w1[d],w2[d],Q1[d],Q2[d],g1,g2)){
			cout<<"fail dimension "<<d<<"\n";
			return false;
		}
	
	}
	
	//verify digest
	
	
	
	if(compute_digest_pub(result,g1) != digestI[dimension-2]){
		cout<<"fail digest\n";
		return false;
	}
	
	return true;
}


bool sum_single_d_verify(vector<snode> bi_digest, vector<Ec1> bi_proof, int result, ZZ_p c0, ZZ_p c1, Ec1 c0_proof, Ec1 c1_proof, Ec1 g1, Ec2 g2){
	{
		Fp12 e1,e2;
		opt_atePairing(e1, bi_digest[1].g2_digest, bi_digest[0].g1_digest);
		opt_atePairing(e2, g2, bi_proof[0]);
		if(e1 != e2){
			cout<<"fail 0\n";
			return false;
		}
	}
	
	for(int i=0;i<bi_proof.size()-1;i++){
		Fp12 e1,e2;
		opt_atePairing(e1, bi_digest[i+2].g2_digest, bi_proof[i]);
		opt_atePairing(e2, g2, bi_proof[i+1]);
		if(e1 != e2){
			cout<<"fail "<<i+1<<"\n";
			return false;
		}
	}
	
	//test
	if(bi_proof[bi_proof.size()-1] == g1*0){
		return true;
	}
	
	//verify sum
	Fp12 e1,e2,e3,e4,e5,e6;
	{
	opt_atePairing(e1,g2,bi_proof[bi_proof.size()-1]);
	opt_atePairing(e2,pubs_g2[1], c0_proof);
	
	
	const mie::Vuint temp(zToString(c0));
	opt_atePairing(e3, g2,g1*temp);
	if(e1!=e2*e3){
		cout<<"c0 fail"<<endl;
		return false;
	}
	}
	{
	
	opt_atePairing(e4,g2,c0_proof);
	opt_atePairing(e5,pubs_g2[1], c1_proof);
	const mie::Vuint temp(zToString(c1));
	opt_atePairing(e6, g2,g1*temp);
	
	if(e4!=e5*e6){
		cout<<"c1 fail"<<endl;
		return false;
	}
	}
	if(result != conv<int>(c1/c0)){
	
		cout<<"sum: "<<result<<"  c1/c0: " <<conv<int>(c1/c0)<<endl;
		return false;
	}
	
	return true;
}


bool sum_multi_d_verify(int dimension, int result, vector<vector<snode> > bi_digest, vector<vector<Ec1> > bi_proof, vector<Ec1> digestI, vector<Ec1> w_extra, vector<Ec2> w1, vector<Ec2> w2, vector<Ec1> Q1, vector<Ec1> Q2, ZZ_p c0, ZZ_p c1, Ec1 c0_proof, Ec1 c1_proof,Ec1 g1, Ec2 g2){
	
	//verify union
	for(int d = 0; d < dimension; d++){
		{
			Fp12 e1,e2;
			opt_atePairing(e1, bi_digest[d][1].g2_digest, bi_digest[d][0].g1_digest);
			opt_atePairing(e2, g2, bi_proof[d][0]);
			if(e1 != e2){
				cout<<"fail 0\n";
				return false;
			}
		}
		
		for(int i=0;i<bi_proof[d].size()-1;i++){
			Fp12 e1,e2;
			opt_atePairing(e1, bi_digest[d][i+2].g2_digest, bi_proof[d][i]);
			opt_atePairing(e2, g2, bi_proof[d][i+1]);
			if(e1 != e2){
				cout<<"fail "<<i+1<<"\n";
				return false;
			}
		}
	}
	
	//test
	//test
	if(digestI[dimension-2] == g1*0){
		return true;
	}
	
	//verify intersection
	
	if(!verify_intersection(digestI[0], w_extra[0], bi_proof[0][bi_proof[0].size()-1], bi_proof[1][bi_proof[1].size()-1], w1[0],w2[0],Q1[0],Q2[0],g1,g2)){
		cout<<"fail dimension 0\n";
		return false;
	}

	for(int d=1; d<dimension-1;d++){
		if(!verify_intersection(digestI[d], w_extra[d], digestI[d-1], bi_proof[d+1][bi_proof[d+1].size()-1], w1[d],w2[d],Q1[d],Q2[d],g1,g2)){
			cout<<"fail dimension "<<d<<"\n";
			return false;
		}
	
	}
	
	//verify sum
	Fp12 e1,e2,e3,e4,e5,e6;
	{
	opt_atePairing(e1,g2,digestI[dimension-2]);
	opt_atePairing(e2,pubs_g2[1], c0_proof);
	
	
	const mie::Vuint temp(zToString(c0));
	opt_atePairing(e3, g2,g1*temp);
	if(e1!=e2*e3){
		cout<<"c0 fail"<<endl;
		return false;
	}
	}
	{
	
	opt_atePairing(e4,g2,c0_proof);
	opt_atePairing(e5,pubs_g2[1], c1_proof);
	const mie::Vuint temp(zToString(c1));
	opt_atePairing(e6, g2,g1*temp);
	
	if(e4!=e5*e6){
		cout<<"c1 fail"<<endl;
		return false;
	}
	}
	if(result != conv<int>(c1/c0)){
	
		cout<<"sum: "<<result<<"  c1/c0: " <<conv<int>(c1/c0)<<endl;
		return false;
	}
	
	return true;
}

//authenticated skiplist functions

void hash_from_path(vector<proofnode> proof, unsigned char* result){
	unsigned char temp1[32],temp2[32];
    
    if(proof[proof.size()-1].flag == 0)
        simpleSHA256(&proof[proof.size()-2].v,NULL,4,0,temp1);
    else
        simpleSHA256(&proof[proof.size()-2].v,&proof[proof.size()-1].v,4,4,temp1);
    
    
    for(int i=proof.size()-3;i>=0;i--){
        if(proof[i].flag == 2)
            simpleSHA256(proof[i].f,temp1,32,32,temp2);
        else if(proof[i].flag == 1)
            simpleSHA256(&proof[i].v,temp1,4,32,temp2);
        else
            simpleSHA256(NULL,temp1,0,32,temp2);
        memcpy(temp1,temp2,32);
        
        
    }
    
	memcpy(result,temp1,32);
	
	return;

}


//bilinear accumulator functions
bn::Ec1 compute_digest_pub(vector<int> array, const bn::Ec1 g1){
	Ec1 digest = g1*0;
	if(array.size()==0)
		return digest;
	
	ZZ_pX f,poly;
	poly=ZZ_pX(INIT_MONO,array.size());
	vec_ZZ_p c;
	c.SetLength(array.size());
	for(int i=0;i<array.size();i++)
		c[i] = conv<ZZ_p>(-array[i]);
	
	BuildFromRoots(poly,c);

	
	for(int i=0;i<array.size()+1;i++){
		
		const mie::Vuint temp(zToString(poly[i]));
		digest = digest+pubs_g1[i]*temp;
	}
	return digest;
}

bn::Ec1 compute_digest_pub_inverse(vector<int> array, const bn::Ec1 g1){
	Ec1 digest = g1*0;
	if(array.size()==0)
		return digest;
	
	ZZ_pX f,poly;
	poly=ZZ_pX(INIT_MONO,array.size());
	vec_ZZ_p c;
	c.SetLength(array.size());
	for(int i=0;i<array.size();i++)
		c[i] = -1/conv<ZZ_p>(array[i]);
	
	BuildFromRoots(poly,c);

	
	for(int i=0;i<array.size()+1;i++){
		
		const mie::Vuint temp(zToString(poly[i]));
		digest = digest+pubs_g1[i]*temp;
	}
	return digest;
}


bn::Ec1 compute_digest_puba(vector<int> array, const bn::Ec1 g1){
	Ec1 digest = g1*0;
	if(array.size()==0)
		return digest;
	
	ZZ_pX f,poly;
	poly=ZZ_pX(INIT_MONO,array.size());
	vec_ZZ_p c;
	c.SetLength(array.size());
	for(int i=0;i<array.size();i++)
		c[i] = conv<ZZ_p>(-array[i]);
	
	BuildFromRoots(poly,c);

	
	for(int i=0;i<array.size()+1;i++){
		
		const mie::Vuint temp(zToString(poly[i]));
		digest = digest+pubas_g1[i]*temp;
	}
	return digest;
}

bn::Ec1 compute_digest_puba_inverse(vector<int> array, const bn::Ec1 g1){
	Ec1 digest = g1*0;
	if(array.size()==0)
		return digest;
	
	ZZ_pX f,poly;
	poly=ZZ_pX(INIT_MONO,array.size());
	vec_ZZ_p c;
	c.SetLength(array.size());
	for(int i=0;i<array.size();i++)
		c[i] = -1/conv<ZZ_p>(array[i]);
	
	BuildFromRoots(poly,c);

	
	for(int i=0;i<array.size()+1;i++){
		
		const mie::Vuint temp(zToString(poly[i]));
		digest = digest+pubas_g1[i]*temp;
	}
	return digest;
}


vector<int> difference(vector<int> a, vector<int> I){
	int i=0,j=0,k=0;
	if(I.size() == 0)
		return a;
	if(a.size() == 0)
		return a;
	
	vector<int> result(a.size()-I.size());
	for(i=0;i<a.size();i++){
		if(a[i]!=I[j]){
			result[k]=a[i];
			k++;
		}
		else{
			if(j<I.size()-1)
				j++;
		}
	
	}
	
	
	return result;
}


vector<int> intersection(vector<int> a, vector<int> b){
	vector<int> I;
	if(a.size()==0 || b.size() == 0){
		I.resize(0);
		return I;
	}
	
	I.resize(a.size());
	int i=0,j=0,k=0;
	while(i<a.size()&&j<b.size()){
		//cout << i << " " << j << "\n";
		if(a[i]==b[j]){
			I[k]=a[i];
			k++;
			i++;
			j++;
		}
		else if(a[i]<b[j]){
			i++;
		}
		else{
			j++;
		}
	}
	I.resize(k);
	return I;
}

void prove_intersection(vector<int>* I, Ec1* digestI, Ec1* w_extra,  vector<int> a, vector<int> b, Ec2* w1, Ec2* w2, Ec1* Q1, Ec1* Q2, Ec1 g1,Ec2 g2){
	vector<int> I_temp,A_I,B_I;
	
	
	if(a.size()==0){
		(*digestI) = g1*0;
		(*I).resize(0);
		(*w_extra) = g1*0;
		(*w1) = g2*0;
		(*w2) = g2*0;
		(*Q1) = g1*0;
		(*Q1) = g1*0;
		cout<<"Empty set in the middle";
	
		return;
	}
	
	
	I_temp = intersection(a,b);
	A_I = difference(a,I_temp);
	B_I = difference(b,I_temp);
	

	
	vec_ZZ_p c;
	
	ZZ_pX polyA,polyB,polyS,polyT,polyD;
	polyA=ZZ_pX(INIT_MONO,0);
	polyB=ZZ_pX(INIT_MONO,0);
	polyS=ZZ_pX(INIT_MONO,0);
	polyT=ZZ_pX(INIT_MONO,0);
	polyD=ZZ_pX(INIT_MONO,0);
	
	

	
	c.SetLength(A_I.size());
	for(int i=0;i<A_I.size();i++)
		c[i] = -A_I[i];
	BuildFromRoots(polyA,c);
	

	
	

	
	c.SetLength(B_I.size());
	for(int i=0;i<B_I.size();i++)
		c[i] = -B_I[i];
	BuildFromRoots(polyB,c);
	
	
	
	Ec2 digest = g2*0;
	for(int i=0;i<polyA.rep.length();i++){
		
		const mie::Vuint temp(zToString(polyA[i]));
		digest = digest+pubs_g2[i]*temp;
	}
	(*w1) = digest;
	
	digest = g2*0;
	for(int i=0;i<polyB.rep.length();i++){
		
		const mie::Vuint temp(zToString(polyB[i]));
		digest = digest+pubs_g2[i]*temp;
	}
	(*w2) = digest;

	XGCD(polyD,polyS,polyT,polyA,polyB);
	
	Ec1 digest1 = g1*0;
	for(int i=0;i<polyS.rep.length();i++){
		
		const mie::Vuint temp(zToString(polyS[i]));
		digest1 = digest1+pubs_g1[i]*temp;
	}
	(*Q1) = digest1;
	
	digest1 = g1*0;
	for(int i=0;i<polyT.rep.length();i++){
		
		const mie::Vuint temp(zToString(polyT[i]));
		digest1 = digest1+pubs_g1[i]*temp;
	}
	(*Q2) = digest1;
	
	
	(*I)=I_temp;
	(*digestI) = compute_digest_pub(I_temp,g1);
	(*w_extra) = compute_digest_puba(I_temp,g1);
	
	return;
	
}

void prove_intersection_inverse(vector<int>* I, Ec1* digestI, Ec1* w_extra,  vector<int> a, vector<int> b, Ec2* w1, Ec2* w2, Ec1* Q1, Ec1* Q2, Ec1 g1,Ec2 g2){
	vector<int> I_temp,A_I,B_I;
	
	if(a.size()==0){
		(*digestI) = g1*0;
		(*I).resize(0);
		(*w_extra) = g1*0;
		(*w1) = g2*0;
		(*w2) = g2*0;
		(*Q1) = g1*0;
		(*Q1) = g1*0;
		cout<<"Empty set in the middle";
	
		return;
	}
	
	I_temp = intersection(a,b);
	A_I = difference(a,I_temp);
	B_I = difference(b,I_temp);
	


	
	vec_ZZ_p c;
	
	ZZ_pX polyA,polyB,polyS,polyT,polyD;
	polyA=ZZ_pX(INIT_MONO,0);
	polyB=ZZ_pX(INIT_MONO,0);
	polyS=ZZ_pX(INIT_MONO,0);
	polyT=ZZ_pX(INIT_MONO,0);
	polyD=ZZ_pX(INIT_MONO,0);
	
	

	
	c.SetLength(A_I.size());
	for(int i=0;i<A_I.size();i++){

		c[i] = -1/conv<ZZ_p>(A_I[i]);
	}
	BuildFromRoots(polyA,c);
	

	
	

	
	c.SetLength(B_I.size());
	for(int i=0;i<B_I.size();i++)
		c[i] = -1/conv<ZZ_p>(B_I[i]);
	BuildFromRoots(polyB,c);
	

	
	Ec2 digest = g2*0;
	for(int i=0;i<polyA.rep.length();i++){
		
		const mie::Vuint temp(zToString(polyA[i]));
		digest = digest+pubs_g2[i]*temp;
	}
	(*w1) = digest;
	
	digest = g2*0;
	for(int i=0;i<polyB.rep.length();i++){
		
		const mie::Vuint temp(zToString(polyB[i]));
		digest = digest+pubs_g2[i]*temp;
	}
	(*w2) = digest;

	XGCD(polyD,polyS,polyT,polyA,polyB);
	
	Ec1 digest1 = g1*0;
	for(int i=0;i<polyS.rep.length();i++){
		
		const mie::Vuint temp(zToString(polyS[i]));
		digest1 = digest1+pubs_g1[i]*temp;
	}
	(*Q1) = digest1;
	
	digest1 = g1*0;
	for(int i=0;i<polyT.rep.length();i++){
		
		const mie::Vuint temp(zToString(polyT[i]));
		digest1 = digest1+pubs_g1[i]*temp;
	}
	(*Q2) = digest1;
	

	
	(*I)=I_temp;
	(*digestI) = compute_digest_pub_inverse(I_temp,g1);
	(*w_extra) = compute_digest_puba_inverse(I_temp,g1);
	
	return;
	
}


bool verify_intersection(Ec1 digestI, Ec1 w_extra, Ec1 a, Ec1 b, Ec2 w1, Ec2 w2, Ec1 Q1, Ec1 Q2, Ec1 g1, Ec2 g2){
	//Ec1 digestI = compute_digest_pub(I,g1);
	Fp12 e1, e2,e3,e4,e5,e6,e7,e8,e9;
	opt_atePairing(e1, w1, digestI);
	opt_atePairing(e2, g2, a);
	//if(e1==e2)
	//	cout << "OK1\n";
	
	opt_atePairing(e3, w2, digestI);
	opt_atePairing(e4, g2, b);
	
	//if(e3==e4)
	//	cout << "OK2\n";
	opt_atePairing(e5, w1, Q1);
	opt_atePairing(e6, w2, Q2);
	opt_atePairing(e7, g2, g1);
	
	//if(e7==e5*e6)
	//	cout << "OK3\n";
	opt_atePairing(e8, pubas_g2,digestI);
	opt_atePairing(e9, g2, w_extra);
	
	
	if(e1 == e2 && e3 == e4 && e5*e6 == e7 && e8==e9)
		return true;
	return false;


}



/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
    /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = (unsigned char*)malloc(c_len);
    
    /* allows reusing of 'e' for multiple encryption cycles */
    EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
    
    /* update ciphertext, c_len is filled with the length of ciphertext generated,
     *len is the size of plaintext in bytes */
    EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
    
    /* update ciphertext with the final remaining bytes */
    EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);
    
    *len = c_len + f_len;
    return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{

    int p_len = *len, f_len = 0;
    unsigned char *plaintext = (unsigned char*)malloc(p_len);
    
    EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
    EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);
    
    *len = p_len + f_len;
    return plaintext;
}

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx,EVP_CIPHER_CTX *d_ctx){
    int i, nrounds = 5;
    unsigned char key[32], iv[32];
    
    /*
     * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
     * nrounds is the number of times the we hash the material. More rounds are more secure but
     * slower.
     */
    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
    if (i != 32) {
        printf("Key size is %d bits - should be 256 bits\n", i);
        return -1;
    }
    
    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    return 0;
}


//hash
bool simpleSHA256(void* input1, void* input2, unsigned long length1, unsigned long length2, unsigned char* md)
{
    SHA256_CTX context;
    if(!SHA256_Init(&context))
        return false;
    if(input1 == NULL){
        
        if(!SHA256_Update(&context, (unsigned char*)input2, length2))
            return false;
        
        if(!SHA256_Final(md, &context))
            return false;
        return true;
    }
    if(input2 == NULL){
        
        if(!SHA256_Update(&context, (unsigned char*)input1, length1))
            return false;
    
        
        if(!SHA256_Final(md, &context))
            return false;
        return true;
    }
    
    
    if(memcmp(input1,input2,4)>0){
    
        if(!SHA256_Update(&context, (unsigned char*)input1, length1))
            return false;
    
        if(!SHA256_Update(&context, (unsigned char*)input2, length2))
            return false;
    
        if(!SHA256_Final(md, &context))
            return false;
    }
    else{
        if(!SHA256_Update(&context, (unsigned char*)input2, length2))
            return false;
        
        if(!SHA256_Update(&context, (unsigned char*)input1, length1))
            return false;
        
        if(!SHA256_Final(md, &context))
            return false;
        
        
    }
    
    return true;
}