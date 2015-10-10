#include "database.hpp"

using namespace std;
using namespace NTL;
using namespace bn;



void single_d_query(string query, int start, int end, int col, vector<int> &result, vector<snode> &bi_digest, vector<Ec1> &bi_proof, Ec1 g1){
	MYSQL_RES *res;
    MYSQL_ROW row;
	
	if (mysql_query(conn, query.c_str())) {
	  fprintf(stderr, "%s\n", mysql_error(conn));
	 exit(1);
	}
	

	int row_num = 0;
	res = mysql_use_result(conn);
	int num_fields = mysql_num_fields(res);
	while ((row = mysql_fetch_row(res)) != NULL){
		if(row[0]!=NULL)
			result.push_back(atoi(row[0]));
		row_num++;
		
	}
	
	sort(result.begin(),result.end());
	
	bi_digest = ss[0][col].range_search(start,end);
	
	vector<vector<int> > sets(bi_digest.size());
	
	
	for(int i=0;i<sets.size();i++){
		sets[i] = ss[0][col].range_cover(&bi_digest[i]);
	}
	
	

	
	
	vector<int> temp_set = sets[0];
	for(int i=1;i<sets.size();i++){
		temp_set.insert(temp_set.end(),sets[i].begin(),sets[i].end());
		bi_proof.push_back(compute_digest_pub(temp_set,g1));
	}
	

	
	return;
}

void single_d_query_inverse(int col2, string query, int start, int end, int col, vector<int> &result, vector<snode> &bi_digest, vector<Ec1> &bi_proof, Ec1 g1){
	MYSQL_RES *res;
    MYSQL_ROW row;
	
	if (mysql_query(conn, query.c_str())) {
	  fprintf(stderr, "%s\n", mysql_error(conn));
	 exit(1);
	}
	

	int row_num = 0;
	res = mysql_use_result(conn);
	int num_fields = mysql_num_fields(res);
	while ((row = mysql_fetch_row(res)) != NULL){
		if(row[0]!=NULL)
			result.push_back(atoi(row[0]));
		row_num++;
		
	}
	
	sort(result.begin(),result.end());
	
	bi_digest = ss_sum[0][col2][col].range_search(start,end);
	
	vector<vector<int> > sets(bi_digest.size());
	
	
	for(int i=0;i<sets.size();i++){
		sets[i] = ss_sum[0][col2][col].range_cover(&bi_digest[i]);
	}
	
	

	
	
	vector<int> temp_set = sets[0];
	for(int i=1;i<sets.size();i++){
		temp_set.insert(temp_set.end(),sets[i].begin(),sets[i].end());
		bi_proof.push_back(compute_digest_pub_inverse(temp_set,g1));
	}
	

	
	return;
}


void sum_single_d_query(string query, int start, int end, int col, int col2, int &result, vector<snode> &bi_digest, vector<Ec1> &bi_proof, ZZ_p &c0, ZZ_p &c1, Ec1 &c0_proof, Ec1 &c1_proof, Ec1 g1){
	MYSQL_RES *res;
    MYSQL_ROW row;
	

	
	if (mysql_query(conn, query.c_str())) {
	  fprintf(stderr, "%s\n", mysql_error(conn));
	 exit(1);
	}
	

	int row_num = 0;
	res = mysql_use_result(conn);
	int num_fields = mysql_num_fields(res);
	while ((row = mysql_fetch_row(res)) != NULL){
		result=atoi(row[0]);
		row_num++;
		
	}
	
	
	bi_digest = ss_sum[0][col2][col].range_search(start,end);
	
	vector<vector<int> > sets(bi_digest.size());
	
	
	for(int i=0;i<sets.size();i++){
		sets[i] = ss_sum[0][col2][col].range_cover(&bi_digest[i]);
	}
	
	

	
	
	vector<int> temp_set = sets[0];
	for(int i=1;i<sets.size();i++){
		temp_set.insert(temp_set.end(),sets[i].begin(),sets[i].end());
		bi_proof.push_back(compute_digest_pub_inverse(temp_set,g1));
	}
	
	
	c0_proof = g1*0;
	c1_proof = g1*0;
	
	ZZ_pX f,poly;
	poly=ZZ_pX(INIT_MONO,temp_set.size());
	vec_ZZ_p c;
	c.SetLength(temp_set.size());
	for(int i=0;i<temp_set.size();i++)
		c[i] = -1/conv<ZZ_p>(temp_set[i]);
	
	BuildFromRoots(poly,c);

	
	c0 = poly[0];
	c1 = poly[1];
	
	for(int i=1;i<temp_set.size()+1;i++){
		
		const mie::Vuint temp(zToString(poly[i]));
		c0_proof = c0_proof+pubs_g1[i-1]*temp;
	}
	
	if(temp_set.size()==1){
		c1_proof = g1*0;
	}
	else{
		for(int i=2;i<temp_set.size()+1;i++){
			
			const mie::Vuint temp(zToString(poly[i]));
			c1_proof = c1_proof+pubs_g1[i-2]*temp;
		}
	}
	return;
}


void multi_d_query(int dimension, vector<string> query, vector<int> start, vector<int> end, vector<int> col, vector<int> &result, vector<vector<snode> > &bi_digest, vector<vector<Ec1> > &bi_proof, vector<Ec1> &digestI, vector<Ec1> &w_extra, vector<Ec2> &w1, vector<Ec2> &w2, vector<Ec1> &Q1, vector<Ec1> &Q2, Ec1 g1, Ec2 g2){
	vector<vector<int> > inter_result(dimension);
	//prove union
	for(int i=0;i<dimension;i++){
		single_d_query(query[i],start[i],end[i],col[i], inter_result[i], bi_digest[i], bi_proof[i], g1);
	}
	

	
	//prove intersection
	vector<int> I_temp=inter_result[0];
	for(int i=0;i<dimension-1;i++){
		prove_intersection(&I_temp, &digestI[i], &w_extra[i], I_temp, inter_result[i+1], &w1[i], &w2[i], &Q1[i], &Q2[i], g1,g2);
	}
	
	result = I_temp;
	

	
	return;
}

void sum_multi_d_query(int dimension, vector<string> query, vector<int> start, vector<int> end, vector<int> col, int col2, int &result, vector<vector<snode> > &bi_digest, vector<vector<Ec1> > &bi_proof, vector<Ec1> &digestI, vector<Ec1> &w_extra, vector<Ec2> &w1, vector<Ec2> &w2, vector<Ec1> &Q1, vector<Ec1> &Q2, ZZ_p &c0, ZZ_p &c1, Ec1 &c0_proof, Ec1 &c1_proof, Ec1 g1, Ec2 g2){
	vector<vector<int> > inter_result(dimension);
	//prove union
	for(int i=0;i<dimension;i++){
		single_d_query_inverse(col2, query[i],start[i],end[i],col[i], inter_result[i], bi_digest[i], bi_proof[i], g1);
	}
	


	
	//prove intersection
	vector<int> I_temp=inter_result[0];
	for(int i=0;i<dimension-1;i++){
		if(I_temp.size()>0)
			prove_intersection_inverse(&I_temp, &digestI[i], &w_extra[i], I_temp, inter_result[i+1], &w1[i], &w2[i], &Q1[i], &Q2[i], g1,g2);
		else 
			break;
	}
	
	if(I_temp.size() == 0){
		result = -1;
		return;
	}
	
	result = 0;
	for(int i=0;i<I_temp.size();i++){
		//cout<<I_temp[i]<<" ";
		result+=I_temp[i];
	}
	
	c0_proof = g1*0;
	c1_proof = g1*0;
	
	ZZ_pX f,poly;
	poly=ZZ_pX(INIT_MONO,I_temp.size());
	vec_ZZ_p c;
	c.SetLength(I_temp.size());
	for(int i=0;i<I_temp.size();i++)
		c[i] = -1/conv<ZZ_p>(I_temp[i]);
	
	BuildFromRoots(poly,c);

	
	c0 = poly[0];
	c1 = poly[1];
	
	for(int i=1;i<I_temp.size()+1;i++){
		
		const mie::Vuint temp(zToString(poly[i]));
		c0_proof = c0_proof+pubs_g1[i-1]*temp;
	}
	
	if(I_temp.size()==1){
		c1_proof = g1*0;
	}
	else{
		for(int i=2;i<I_temp.size()+1;i++){
			
			const mie::Vuint temp(zToString(poly[i]));
			c1_proof = c1_proof+pubs_g1[i-2]*temp;
		}
	}

	
	return;
}

int maxmin(string query){
	MYSQL_RES *res;
    MYSQL_ROW row;
	
	
	int result=-1;
	
	if (mysql_query(conn, query.c_str())) {
	  fprintf(stderr, "%s\n", mysql_error(conn));
	 exit(1);
	}

	int row_num = 0;
	res = mysql_use_result(conn);
	
	int num_fields = mysql_num_fields(res);;
	while ((row = mysql_fetch_row(res)) != NULL){
		if(row[0]!=NULL){
			result=atoi(row[0]);
		}
		row_num++;
		
	}
	
	
	return result;
}