#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#define n 5
#define m 100

int main(){
    FILE* f = fopen("table1.txt","w");
    srand(time(NULL));
    fprintf(f,"%d %d\n",n,m);

    for(int i=0;i<n;i++){
        fprintf(f,"column%d\t",i);
    }
    fprintf(f,"\n");
    for(int i=0;i<m;i++){
        fprintf(f,"%d\t",i+1);
	fprintf(f,"%d\t",i+2);
        for(int j=0;j<n-2;j++){
            fprintf(f,"%d\t",rand()%1000*1000+i+j);
        }
        fprintf(f,"\n");
    }
    fclose(f);
    return 0;
}
