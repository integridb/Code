#include <iostream>
#include <vector>
#include <cstdlib>
#include <algorithm>

using namespace std;

int main(){
	srand(1);
	vector<vector<int> > test(10);
	for(int i=0;i<10;i++){
		test[i].resize(2);
		test[i][0] = rand()%100;
		test[i][1] = rand()%100;
	}
	
	for(int i=0;i<2;i++){
		for(int j=0;j<10;j++)
			cout<<test[j][i]<<" ";
		cout<<"\n";
	}
	
	sort(test.begin(),test.end());
	for(int i=0;i<2;i++){
		for(int j=0;j<10;j++)
			cout<<test[j][i]<<" ";
		cout<<"\n";
	}
	
	return 0;
}