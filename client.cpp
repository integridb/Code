#include "database.hpp"

using namespace std;
using namespace NTL;
using namespace bn;


EVP_CIPHER_CTX en, de;
ZZ_p s;
MYSQL *conn;

//public keys

vector<Ec1> pubs_g1(q+1);
vector<Ec2> pubs_g2(q+1);
vector<Ec1> pubas_g1(q+1);
Ec2 pubas_g2;

//encryption
//int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx,EVP_CIPHER_CTX *d_ctx);

//bilinear
bn::Ec1 compute_digest(vector<int> array, const bn::Ec1 g1);

ZZ_p setup_bilinear(Ec1 g1, Ec2 g2);

//database client 

void setup(vector<vector<int> > &table, vector<string>  &name);
void setup_sqlserver(vector<vector<int> > table, vector<string>  name);
void update_client(vector<int> update_row, Ec1 g1, Ec2 g2);

std::vector<std::vector<skiplist> > ss(1);
std::vector<std::vector<std::vector<skiplist> > > ss_sum(1);

int main(){

	clock_t t1,t2;
    //random
	srand(time(NULL));
	
    //initialization
	
	cout<<"initialize encrytion, g1, g2, s, a\n";
	
	t1 = clock();
	
    unsigned int salt[] = {12345, 54321};
    unsigned char key_data[] = "0123456789012345678901234567890";
    int key_data_len = 32, i;
    
	ZZ p=conv<ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
	ZZ_p::init(p);
    random(s);
	
	//bilinear g1 g2
	bn::CurveParam cp = bn::CurveFp254BNb;
	Param::init(cp);
	const Point& pt = selectPoint(cp);
	const Ec2 g2(
		Fp2(Fp(pt.g2.aa), Fp(pt.g2.ab)),
		Fp2(Fp(pt.g2.ba), Fp(pt.g2.bb))
	);
	const Ec1 g1(pt.g1.a, pt.g1.b);
	
	t2 = clock();
	cout<<"time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
	
	cout<<"generate public key\n";
	
	
	t1 = clock();
	
	setup_bilinear(g1,g2);
	
	t2 = clock();
	cout<<"time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
    
    /* gen key and iv. init the cipher ctx object */
    if (aes_init(key_data, key_data_len, (unsigned char *)&salt, &en, &de)) {
        printf("Couldn't initialize AES cipher\n");
        return -1;
    }
    
	//load tables
	
	
	cout<<"load table to server\n";
	t1 = clock();
	
	
    vector<vector<vector<int> > > tables(10);
    vector<vector<string> > column_name(10);
    setup(tables[0],column_name[0]);
    
	//connect to server
	
	char *server = "localhost";
    char *user = "root";
    char *password = "root";
    char *database = "integridb";

    conn = mysql_init(NULL);
	/* Connect to database */
	if (!mysql_real_connect(conn, server,
	  user, password, database, 0, NULL, 0)) {
	  fprintf(stderr, "%s\n", mysql_error(conn));
	  exit(1);
	}
	
	//load tables to sql server
    setup_sqlserver(tables[0],column_name[0]);
	    
		
	t2 = clock();
	cout<<"time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
		
    //compute skiplists

	cout<<"computes skip lists\n";
	
	t1=clock();
	
    ss[0].resize(tables[0].size());
    for(int i=0;i<tables[0].size();i++){
		vector<vector<int> > sort_col(tables[0][i].size());
		
		for(int l=0;l<sort_col.size();l++){
			sort_col[l].resize(2);
			sort_col[l][0] = tables[0][i][l];
			sort_col[l][1] = tables[0][0][l];
		}
		
		sort(sort_col.begin(),sort_col.end());
		
		//sort(tables[0][i].begin(),tables[0][i].end());
        //for(int j=0;j<tables[0][i].size();j++){
		for(int j=sort_col.size()-1;j>0;j--){
            //cout<<j<<": "<<tables[0][i][j]<<"\n";
            //ss[0][i].insert_element(tables[0][i][j],tables[0][0][j],s, g1,g2);
			ss[0][i].insert_element_inorder(sort_col[j][0],sort_col[j][1],s,g1,g2);
        }
		
		ss[0][i].insert_element(sort_col[0][0],sort_col[0][1],s,g1,g2);
		
    }
	
	
	ss_sum[0].resize(tables[0].size());
    for(int i=0;i<tables[0].size();i++){
		ss_sum[0][i].resize(tables[0].size());
		for(int j=0; j<tables[0].size();j++){
			
			vector<vector<int> > sort_col(tables[0][i].size());
			for(int l=0;l<sort_col.size();l++){
				sort_col[l].resize(2);
				sort_col[l][0] = tables[0][j][l];
				sort_col[l][1] = tables[0][i][l];
			}
			
			sort(sort_col.begin(),sort_col.end());
			
			//for(int k=0;k<tables[0][i].size();k++){
				//ss_sum[0][i][j].insert_element_inverse(tables[0][j][k], tables[0][i][k], s, g1,g2);
			for(int k=sort_col.size()-1;k>0;k--){
				ss_sum[0][i][j].insert_element_inverse_inorder(sort_col[k][0],sort_col[k][1],s,g1,g2);
			}
			
			
			
			ss_sum[0][i][j].insert_element_inverse(sort_col[0][0],sort_col[0][1],s,g1,g2);
		}
	}

	
	
	t2 = clock();
	cout<<"time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
	
	int option;
	
	while(1){
		cout<<endl<<"-----------------------"<<endl;
        cout<<endl<<"Operations"<<endl;
        cout<<endl<<"-----------------------"<<endl;
		cout<<"0.Exit"<<endl;
        cout<<"1.Single Dimensional Query"<<endl;
        cout<<"2.Update"<<endl;
        cout<<"3.Multi Dimensional Query"<<endl;
		cout<<"4.Sum Single Dimensional Query"<<endl;
		cout<<"5.Sum Multi Dimensional Query"<<endl;
		cout<<"6.Count Single Dimensional Query"<<endl;
		cout<<"7.Count Multi Dimensional Query"<<endl;
		cout<<"8.MAX Query"<<endl;
		cout<<"9.MIN Query"<<endl;
        cout<<"10.test"<<endl;
        cout<<"Enter your choice : ";
		cin>>option;
		
		switch(option){
		
			case 0:
				exit(1);
				break;
				
			case 1:{
			//single dimensional query
			
			
				{
				int col = rand()%(tables[0].size());
				
				int start = 0,end = 0;
				
				while(start>=end){
					start = tables[0][col][rand()%tables[0][col].size()];
					end = tables[0][col][rand()%tables[0][col].size()];
				}
				
				string query = "SELECT column0 FROM Table1 WHERE column" +to_string(col)+" BETWEEN "+to_string(start)+" AND "+to_string(end)+";";
				cout<<query<<endl;
				vector<int> result;
				vector<snode> bi_digest;
				vector<Ec1> bi_proof;
				
				t1 = clock();
				
				single_d_query(query, start, end, col, result, bi_digest, bi_proof,g1);
				
				t2 = clock();
					cout<<"prover time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
				
				if(result.size() == 0)
					cout<<"empty";
				
				for(int i=0;i<result.size();i++)
					cout<<result[i]<<" ";
				cout<<endl;
				
				
				t1 = clock();
				
				if(single_d_verify(bi_digest,bi_proof,result,g1,g2))
					cout<<"Verified!\n";
				else
					cout<<"Failed...\n";
				}
				
				t2 = clock();
					cout<<"verification time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
			
				break;
			}
			/*
			ss[0][0].display();
			vector<snode> result = ss[0][0].range_search(tables[0][1][20],tables[0][1][35]);
			for(int i=0;i<result.size();i++){
				PUT(result[i].g1_digest);
				PUT(result[i].g2_digest);
			}
			*/
			
			case 2:{
			//update
			
				vector<int> update_row(tables[0].size());
				update_row[0] = tables[0][0][tables[0][0].size()-1]+1;
				update_row[1] = tables[0][0][tables[0][0].size()-1]+2;
				for(int i=2;i<update_row.size();i++)
					update_row[i] = rand()%10000;
				for(int i=0;i<update_row.size();i++)
					tables[0][i].push_back(update_row[i]);
					
				t1 = clock();
					
				update_client(update_row, g1, g2);
				
				
				t2 = clock();
					cout<<"update time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
				
				break;
			}
			
			case 3:{
			//multi dimensional query
			
				{
				
				
				
				int dimension = rand()%(tables[0].size()-2)+2;
				
				vector<int> col(dimension);
				vector<int> start(dimension,0);
				vector<int> end(dimension,0)
				;
				for(int i=0;i<dimension;i++){
					col[i] = i+1;
					while(start[i]>=end[i]){
						start[i] = tables[0][col[i]][rand()%tables[0][col[i]].size()];
						end[i] = tables[0][col[i]][rand()%tables[0][col[i]].size()];
					}
				}
				
				
				
				vector<string> query(dimension);
				for(int i=0;i<dimension;i++){
					query[i] = "SELECT column0 FROM Table1 WHERE column"+to_string(col[i])+" BETWEEN "+to_string(start[i])+" AND "+to_string(end[i])+";";
				}
				
				vector<int> result;
				vector<vector<snode> > bi_digest(dimension);
				vector<vector<Ec1> > bi_proof(dimension);
				vector<Ec1> digestI(dimension-1);
				vector<Ec1> w_extra(dimension-1);
				vector<Ec2> w1(dimension-1);
				vector<Ec2> w2(dimension-1);
				vector<Ec1> Q1(dimension-1);
				vector<Ec1> Q2(dimension-1);
				
				string mysql_query = "SELECT column0 FROM Table1 WHERE ";
				for(int i=0;i<dimension;i++){
					mysql_query+="(column"+to_string(col[i])+" BETWEEN "+to_string(start[i])+" AND "+to_string(end[i])+")";
					if(i<dimension-1)
						mysql_query+=" AND ";
				}
				mysql_query+=";";
				cout<<mysql_query<<endl;
				
				t1 = clock();
				
				multi_d_query(dimension, query, start,end, col, result, bi_digest, bi_proof, digestI, w_extra, w1, w2, Q1, Q2, g1, g2);
				
				t2 = clock();
					cout<<"prover time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
				
				if(result.size() == 0)
					cout<<"empty";
				
				for(int i=0;i<result.size();i++)
					cout<<result[i]<<" ";
				cout<<endl;
				
				t1 = clock();
				
				if(multi_d_verify(dimension, result, bi_digest, bi_proof, digestI, w_extra, w1, w2, Q1, Q2, g1, g2))
					cout<<"Verified!\n";
				else
					cout<<"Failed...\n";
				}
				
				t2 = clock();
					cout<<"verification time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
			
				break;
			}
			case 4:
			//single dimension sum
				{
				int col = rand()%(tables[0].size()-1)+1;
				int col2 = rand()%(tables[0].size()-1)+1;
				
				int start = 0,end = 0;
				
				while(start>=end){
					start = tables[0][col][rand()%tables[0][col].size()];
					end = tables[0][col][rand()%tables[0][col].size()];
				}
				
				string query = "SELECT SUM(column"+to_string(col2)+") FROM Table1 WHERE column" +to_string(col)+" BETWEEN "+to_string(start)+" AND "+to_string(end);
				cout<<query<<endl;
				
				int result;
				vector<snode> bi_digest;
				vector<Ec1> bi_proof;
				Ec1 c0_proof,c1_proof;
				ZZ_p c0,c1;
				
				t1 = clock();
				
				sum_single_d_query(query, start, end, col,col2, result, bi_digest, bi_proof,c0,c1,c0_proof,c1_proof,g1);
				
				t2 = clock();
					cout<<"prover time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
				
				cout<<"sum is :"<<result<<endl;
				
				
				t1 = clock();
				
				if(sum_single_d_verify(bi_digest,bi_proof,result, c0,c1,c0_proof,c1_proof, g1,g2))
					cout<<"Verified!\n";
				else
					cout<<"Failed...\n";
				
				
				t2 = clock();
					cout<<"verification time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
			
			
				break;
				}
			
			case 5:
			//multi dimension sum
				{
				int dimension = rand()%(tables[0].size()-2)+2;
				int col2 = rand()%(tables[0].size()-1)+1;
				
				vector<int> col(dimension);
				vector<int> start(dimension,0);
				vector<int> end(dimension,0)
				;
				for(int i=0;i<dimension;i++){
					col[i] = i+1;
					while(start[i]>=end[i]){
						start[i] = tables[0][col[i]][rand()%tables[0][col[i]].size()];
						end[i] = tables[0][col[i]][rand()%tables[0][col[i]].size()];
					}
				}
				
				
				
				vector<string> query(dimension);
				for(int i=0;i<dimension;i++){
					query[i] = "SELECT column"+to_string(col2)+" FROM Table1 WHERE column"+to_string(col[i])+" BETWEEN "+to_string(start[i])+" AND "+to_string(end[i])+";";
				}
				
				int result;
				vector<vector<snode> > bi_digest(dimension);
				vector<vector<Ec1> > bi_proof(dimension);
				vector<Ec1> digestI(dimension-1);
				vector<Ec1> w_extra(dimension-1);
				vector<Ec2> w1(dimension-1);
				vector<Ec2> w2(dimension-1);
				vector<Ec1> Q1(dimension-1);
				vector<Ec1> Q2(dimension-1);
				Ec1 c0_proof,c1_proof;
				ZZ_p c0,c1;
				
				string mysql_query = "SELECT SUM(column"+to_string(col2)+") FROM Table1 WHERE ";
				for(int i=0;i<dimension;i++){
					mysql_query+="(column"+to_string(col[i])+" BETWEEN "+to_string(start[i])+" AND "+to_string(end[i])+")";
					if(i<dimension-1)
						mysql_query+=" AND ";
				}
				mysql_query+=";";
				cout<<mysql_query<<endl;
				
				t1 = clock();
				
				sum_multi_d_query(dimension, query, start,end, col,col2, result, bi_digest, bi_proof, digestI, w_extra, w1, w2, Q1, Q2,c0,c1,c0_proof,c1_proof, g1, g2);
				
				t2 = clock();
					cout<<"prover time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
				
				
				cout<<"sum is:"<<result<<endl;
				
				if(result != -1){
				
					t1 = clock();
					
					if(sum_multi_d_verify(dimension, result, bi_digest, bi_proof, digestI, w_extra, w1, w2, Q1, Q2, c0,c1,c0_proof,c1_proof,g1, g2))
						cout<<"Verified!\n";
					else
						cout<<"Failed...\n";
				
					
					t2 = clock();
						cout<<"verification time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
				}
				break;
				}
			
			case 6:
				{
				//single dimension count
				
				int col = rand()%(tables[0].size()-1)+1;
				int col2 = 0;
				int col3 = 1;
				
				int start = 0,end = 0;
				
				while(start>=end){
					start = tables[0][col][rand()%tables[0][col].size()];
					end = tables[0][col][rand()%tables[0][col].size()];
				}
				
				string query1 = "SELECT SUM(column"+to_string(col2)+") FROM Table1 WHERE column" +to_string(col)+" BETWEEN "+to_string(start)+" AND "+to_string(end);
				string query2 = "SELECT SUM(column"+to_string(col3)+") FROM Table1 WHERE column" +to_string(col)+" BETWEEN "+to_string(start)+" AND "+to_string(end);
				
				cout<<"SELECT COUNT(column"<<to_string(col2)<<") FROM Table1 WHERE column" <<to_string(col)<<" BETWEEN "<<to_string(start)<<" AND "<<to_string(end)<<endl;
				
				int result, result2;
				vector<snode> bi_digest, bi_digest2;
				vector<Ec1> bi_proof, bi_proof2;
				Ec1 c0_proof,c1_proof, c0_proof2,c1_proof2;
				ZZ_p c0,c1,c02,c12;
				
				t1 = clock();
				
				sum_single_d_query(query1, start, end, col,col2, result, bi_digest, bi_proof,c0,c1,c0_proof,c1_proof,g1);
				sum_single_d_query(query2, start, end, col,col3, result2, bi_digest2, bi_proof2,c02,c12,c0_proof2,c1_proof2,g1);
				
				t2 = clock();
					cout<<"prover time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
				
				cout<<"count is :"<<result2-result<<endl;
				
				t1 = clock();
				
				if(sum_single_d_verify(bi_digest,bi_proof,result, c0,c1,c0_proof,c1_proof, g1,g2)&&sum_single_d_verify(bi_digest2,bi_proof2,result2, c02,c12,c0_proof2,c1_proof2, g1,g2))
					cout<<"Verified!\n";
				else
					cout<<"Failed...\n";
				
				
				t2 = clock();
					cout<<"verification time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
					
				break;
			
				}
			
			case 7:
			{
			int dimension = rand()%(tables[0].size()-2)+2;
				int col2 = 0, col3 = 1;
				
				vector<int> col(dimension);
				vector<int> start(dimension,0);
				vector<int> end(dimension,0)
				;
				for(int i=0;i<dimension;i++){
					col[i] = i+1;
					while(start[i]>=end[i]){
						start[i] = tables[0][col[i]][rand()%tables[0][col[i]].size()];
						end[i] = tables[0][col[i]][rand()%tables[0][col[i]].size()];
					}
				}
				
				
				
				vector<string> query(dimension),query2(dimension);
				for(int i=0;i<dimension;i++){
					query[i] = "SELECT column"+to_string(col2)+" FROM Table1 WHERE column"+to_string(col[i])+" BETWEEN "+to_string(start[i])+" AND "+to_string(end[i])+";";
					query2[i] = "SELECT column"+to_string(col3)+" FROM Table1 WHERE column"+to_string(col[i])+" BETWEEN "+to_string(start[i])+" AND "+to_string(end[i])+";";
				}
				
				int result,result2;
				vector<vector<snode> > bi_digest(dimension),bi_digest2(dimension);
				vector<vector<Ec1> > bi_proof(dimension),bi_proof2(dimension);
				vector<Ec1> digestI(dimension-1),digestI2(dimension-1);
				vector<Ec1> w_extra(dimension-1),w_extra2(dimension-1);
				vector<Ec2> w1(dimension-1),w12(dimension-1);
				vector<Ec2> w2(dimension-1),w22(dimension-1);
				vector<Ec1> Q1(dimension-1),Q12(dimension-1);
				vector<Ec1> Q2(dimension-1),Q22(dimension-1);
				Ec1 c0_proof,c1_proof,c0_proof2,c1_proof2;
				ZZ_p c0,c1,c02,c12;
				
				string mysql_query = "SELECT COUNT(column"+to_string(col2)+") FROM Table1 WHERE ";
				for(int i=0;i<dimension;i++){
					mysql_query+="(column"+to_string(col[i])+" BETWEEN "+to_string(start[i])+" AND "+to_string(end[i])+")";
					if(i<dimension-1)
						mysql_query+=" AND ";
				}
				mysql_query+=";";
				cout<<mysql_query<<endl;
				
				t1 = clock();
				
				sum_multi_d_query(dimension, query, start,end, col,col2, result, bi_digest, bi_proof, digestI, w_extra, w1, w2, Q1, Q2,c0,c1,c0_proof,c1_proof, g1, g2);
				sum_multi_d_query(dimension, query2, start,end, col,col3, result2, bi_digest2, bi_proof2, digestI2, w_extra2, w12, w22, Q12, Q22,c02,c12,c0_proof2,c1_proof2, g1, g2);
				
				t2 = clock();
					cout<<"prover time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
				
				
				cout<<"count is:"<<result2-result<<endl;
				
				if(result != -1){
				
					t1 = clock();
					
					if(sum_multi_d_verify(dimension, result, bi_digest, bi_proof, digestI, w_extra, w1, w2, Q1, Q2, c0,c1,c0_proof,c1_proof,g1, g2)&&sum_multi_d_verify(dimension, result2, bi_digest2, bi_proof2, digestI2, w_extra2, w12, w22, Q12, Q22, c02,c12,c0_proof2,c1_proof2,g1, g2))
						cout<<"Verified!\n";
					else
						cout<<"Failed...\n";
				
					
					t2 = clock();
						cout<<"verification time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
				}
				break;
			
			}
			
			
			case 8:
				{
				int dimension = rand()%(tables[0].size()-1)+1;
				int col2 = rand()%(tables[0].size()-1)+1;
				
				vector<int> col(dimension+1);
				vector<int> start(dimension+1,0);
				vector<int> end(dimension+1,0)
				;
				for(int i=0;i<dimension;i++){
					col[i] = i+1;
					while(start[i]>=end[i]){
						start[i] = tables[0][col[i]][rand()%tables[0][col[i]].size()];
						end[i] = tables[0][col[i]][rand()%tables[0][col[i]].size()];
					}
				}
				
				string mysql_query = "SELECT MAX(column"+to_string(col2)+") FROM Table1 WHERE ";
				for(int i=0;i<dimension;i++){
					mysql_query+="(column"+to_string(col[i])+" BETWEEN "+to_string(start[i])+" AND "+to_string(end[i])+")";
					if(i<dimension-1)
						mysql_query+=" AND ";
				}
				mysql_query+=";";
				cout<<mysql_query<<endl;
				
				int max = maxmin(mysql_query);
				
				
				if(max!=-1){
				
					dimension++;
					
					vector<string> query(dimension);
					for(int i=0;i<dimension-1;i++){
						query[i] = "SELECT column"+to_string(col2)+" FROM Table1 WHERE column"+to_string(col[i])+" BETWEEN "+to_string(start[i])+" AND "+to_string(end[i])+";";
					}
					query[dimension-1] = "SELECT column"+to_string(col2)+" FROM Table1 WHERE column"+to_string(col2)+" BETWEEN "+to_string(max)+" AND "+to_string(INF-1)+";";
					start[dimension-1] = max;
					end[dimension-1] = INF-1;
					col[dimension-1] = col2;
					
					int result;
					vector<vector<snode> > bi_digest(dimension);
					vector<vector<Ec1> > bi_proof(dimension);
					vector<Ec1> digestI(dimension-1);
					vector<Ec1> w_extra(dimension-1);
					vector<Ec2> w1(dimension-1);
					vector<Ec2> w2(dimension-1);
					vector<Ec1> Q1(dimension-1);
					vector<Ec1> Q2(dimension-1);
					Ec1 c0_proof,c1_proof;
					ZZ_p c0,c1;
					
					
					t1 = clock();
					
					sum_multi_d_query(dimension, query, start,end, col,col2, result, bi_digest, bi_proof, digestI, w_extra, w1, w2, Q1, Q2, c0,c1,c0_proof,c1_proof,g1, g2);
					
					t2 = clock();
						cout<<"prover time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
					
					cout<<"result is:"<<result<<endl;
					
					
					
					
					
					if(result != -1){
					
						t1 = clock();
						
						if(sum_multi_d_verify(dimension, result, bi_digest, bi_proof, digestI, w_extra, w1, w2, Q1, Q2, c0,c1,c0_proof,c1_proof,g1, g2) && result == max)
							cout<<"Verified!\n";
						else
							cout<<"Failed...\n";
					
						
						t2 = clock();
							cout<<"verification time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
					}	
					else{
					
						cout<<"Verified!\n";
					}
				
				}
				break;
				
			}
				
			
			case 9:
			{
				int dimension = rand()%(tables[0].size()-1)+1;
				int col2 = rand()%(tables[0].size()-1)+1;
				
				vector<int> col(dimension+1);
				vector<int> start(dimension+1,0);
				vector<int> end(dimension+1,0);
				for(int i=0;i<dimension;i++){
					col[i] = i+1;
					while(start[i]>=end[i]){
						start[i] = tables[0][col[i]][rand()%tables[0][col[i]].size()];
						end[i] = tables[0][col[i]][rand()%tables[0][col[i]].size()];
					}
				}
				
				string mysql_query = "SELECT MIN(column"+to_string(col2)+") FROM Table1 WHERE ";
				for(int i=0;i<dimension;i++){
					mysql_query+="(column"+to_string(col[i])+" BETWEEN "+to_string(start[i])+" AND "+to_string(end[i])+")";
					if(i<dimension-1)
						mysql_query+=" AND ";
				}
				mysql_query+=";";
				cout<<mysql_query<<endl;
				
				int min = maxmin(mysql_query);
				
				
				if(min!=-1){
				
					dimension++;
					
					vector<string> query(dimension);
					for(int i=0;i<dimension-1;i++){
						query[i] = "SELECT column"+to_string(col2)+" FROM Table1 WHERE column"+to_string(col[i])+" BETWEEN "+to_string(start[i])+" AND "+to_string(end[i])+";";
					}
					query[dimension-1] = "SELECT column"+to_string(col2)+" FROM Table1 WHERE column"+to_string(col2)+" BETWEEN "+to_string(0)+" AND "+to_string(min)+";";
					start[dimension-1] = 0;
					end[dimension-1] = min;
					col[dimension-1] = col2;
					
					int result;
					vector<vector<snode> > bi_digest(dimension);
					vector<vector<Ec1> > bi_proof(dimension);
					vector<Ec1> digestI(dimension-1);
					vector<Ec1> w_extra(dimension-1);
					vector<Ec2> w1(dimension-1);
					vector<Ec2> w2(dimension-1);
					vector<Ec1> Q1(dimension-1);
					vector<Ec1> Q2(dimension-1);
					Ec1 c0_proof,c1_proof;
					ZZ_p c0,c1;
					
					
					t1 = clock();
					
					sum_multi_d_query(dimension, query, start,end, col,col2, result, bi_digest, bi_proof, digestI, w_extra, w1, w2, Q1, Q2, c0,c1,c0_proof,c1_proof,g1, g2);
					
					t2 = clock();
						cout<<"prover time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
					
					cout<<"result is:"<<result<<endl;
					
					
					
					
					
					if(result != -1){
					
						t1 = clock();
						
						if(sum_multi_d_verify(dimension, result, bi_digest, bi_proof, digestI, w_extra, w1, w2, Q1, Q2, c0,c1,c0_proof,c1_proof,g1, g2) && result == min)
							cout<<"Verified!\n";
						else
							cout<<"Failed...\n";
					
						
						t2 = clock();
							cout<<"verification time: "<<(double)(t2-t1)/CLOCKS_PER_SEC<<"s\n";
					}	
					else{
					
						cout<<"Verified!\n";
					}
				
				}
				break;
			}
			
			case 10:
				{
				
					for(int col = 0; col< tables[0].size();col++){
						for(int j = 0; j<tables[0][col].size(); j++){
							int element = tables[0][col][j];
							//cout<<col<<" "<<element<<endl;
							
							unsigned char test[32];
							hash_from_path(ss[0][col].prove_path(element),test);
							if(memcmp(test, ss[0][col].header->hash, 32)==0){
								//cout<<"Path verified!!\n";
							}
							else{
								cout<<"Failed ... "<<col<<"\n";
								exit(0);
								
							}
							
							for(int col2 = 0;col2< tables[0].size();col2++){
								hash_from_path(ss_sum[0][col2][col].prove_path(element),test);
								if(memcmp(test, ss_sum[0][col2][col].header->hash, 32)==0){
									//cout<<"Path verified!!\n";
								}
								else{
									cout<<"Failed ... "<<col<<" "<<col2<<"\n";
									exit(0);
									
								}
							}
						}
					}
					
					break;
				}
			
			default:
				cout<<"wrong option\n";
		
		}
	}
}



ZZ_p setup_bilinear(Ec1 g1, Ec2 g2){



	//s and public key
	//g1 pub
	ZZ_p temp1,temp2;
	random(s);
	
	
	
	for(int i=0;i<q+1;i+=1){
		temp2=conv<ZZ_p>(i);
		power(temp1,s,i);
		const mie::Vuint temp(zToString(temp1));
		pubs_g1[i]=g1*temp;
	}
	//g2 pub
	for(int i=0;i<q+1;i+=1){
		temp2=conv<ZZ_p>(i);
		power(temp1,s,i);
		const mie::Vuint temp(zToString(temp1));
		pubs_g2[i]=g2*temp;
	}
	//g1 a pub
	ZZ_p a;
	random(a);
	for(int i=0;i<q+1;i+=1){
		temp2=conv<ZZ_p>(i);
		power(temp1,s,i);
		const mie::Vuint temp(zToString(temp1*a));
		pubas_g1[i]=g1*temp;
	}
	
	//g2 a pub
	{
	const mie::Vuint temp(zToString(a));
	pubas_g2=g2*temp;
	}
	return s;
}

void setup(vector<vector<int> > &table, vector<string>  &name){

    
    std::fstream f("table1.txt", std::ios_base::in);

    int n,m;
    f>>n>>m;
    table.resize(n);
    name.resize(n);

    for(int i=0;i<n;i++)
        table[i].resize(m);
    for(int i=0;i<n;i++){
        f>>name[i];
    }
    for(int i=0;i<m;i++){
        for(int j=0;j<n;j++)
            f>>table[j][i];
    }
  
    return;
}

void setup_sqlserver(vector<vector<int> > table, vector<string>  name){

	/* send SQL query */
	if (mysql_query(conn, "DROP TABLE IF EXISTS Table1;")) {
	  fprintf(stderr, "%s\n", mysql_error(conn));
	 exit(1);
	}
	
	string query = "CREATE TABLE Table1 (";
	for(int i=0;i<name.size()-1;i++){
		query.append(name[i]+" int, ");
	}
	query.append(name[name.size()-1]+" int);");
	
	//cout<<query<<endl;
	
	if (mysql_query(conn, query.c_str())) {
	  fprintf(stderr, "%s\n", mysql_error(conn));
	 exit(1);
	}
	
	for(int i=0;i<table[0].size();i++){
		query.clear();
		query = "insert into Table1 values (";
		for(int j=0;j<table.size()-1;j++){
			query.append(to_string(table[j][i])+", ");
		}
		query.append(to_string(table[table.size()-1][i])+");");
		//cout<<query<<endl;
		if (mysql_query(conn, query.c_str())) {
			fprintf(stderr, "%s\n", mysql_error(conn));
			exit(1);
		}
	}
	
	return;
	

}


void update_client(vector<int> update_row, Ec1 g1, Ec2 g2){
	//cout<<update_row.size()<<endl;
	//for(int i=0;i<update_row.size();i++)
	//	cout<<update_row[i]<<" ";
	//cout<<endl;

	for(int i=0;i<update_row.size();i++){
		ss[0][i].insert_element(update_row[i],update_row[0],s, g1,g2);
	
	}
	
	for(int i=0;i<update_row.size();i++){
		for(int j=0;j<update_row.size();j++){
			ss_sum[0][i][j].insert_element_inverse(update_row[j],update_row[i],s, g1,g2);
		}
	
	}
	
	string query = "insert into Table1 values (";
	for(int i=0;i<update_row.size()-1;i++){
		query.append(to_string(update_row[i])+", ");
	}
	query.append(to_string(update_row[update_row.size()-1])+");");
	cout<<query<<endl;
	if (mysql_query(conn, query.c_str())) {
		fprintf(stderr, "%s\n", mysql_error(conn));
		exit(1);
	}
	return;
}


bn::Ec1 compute_digest(vector<int> array, const bn::Ec1 g1){
	Ec1 digest;
	if(array.size()==0)
		return digest;
	
	ZZ_p temp1=conv<ZZ_p>(1);
	for(int i=0;i<array.size();i++){
		temp1 *= s+array[i];
		
	}
	const mie::Vuint temp(zToString(temp1));
		digest=g1*temp;
	return digest;
}





