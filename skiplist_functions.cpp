#include "database.hpp"

using namespace std;
using namespace NTL;
using namespace bn;


void compute_hash(snode* a){
	if(a->down == NULL){
		if(a->right == NULL){
			simpleSHA256(&a->value, &a->right0->value, 4, 4, a->hash);
		}
		else{
			simpleSHA256(&a->value, a->right->hash, 4, 32, a->hash);
		}
	
	}
	else{
		if(a->right == NULL){
			simpleSHA256(a->down->hash, NULL, 32, 0, a->hash);
		}
		else{
			simpleSHA256(a->down->hash,a->right->hash,32,32,a->hash);
		}
	
	}
	return;

}


//skiplist functions:
/*
 * Random Value Generator
 */
float frand()
{
    return (float) rand() / RAND_MAX;
}

/*
 * Random Level Generator
 */
int random_level()
{
    static bool first = true;
    if (first)
    {
        srand((unsigned)time(NULL));
        first = false;
    }
    int lvl = (int)(log(frand()) / log(1.-P));
    if (lvl>MAX_LEVEL-1)
        lvl = MAX_LEVEL-1;
    return lvl+1;
}

/*
 * Insert Element in Skip List
 */


void skiplist::insert_element(int value, int rowID, ZZ_p s, Ec1 g1, Ec2 g2)
{
    snode *x = header;
    if(skiplist::contains(value)){
        cout<<"element in the list.\n";
        return;
    }
    
    //find insert points
    
    std::vector<snode*> temp(MAX_LEVEL);
	vector<snode*> path_node;
	path_node.push_back(x);
    
    for(int i=MAX_LEVEL-1;i>0;i--){
        while (x->right != NULL && x->right->value <= value)
        {
            x = x->right;
			path_node.push_back(x);
        }
        temp[i]=x;
        x=x->down;
		path_node.push_back(x);
    }
    while (x->right != NULL && x->right->value < value)
    {
        x = x->right;
		path_node.push_back(x);
    }
    temp[0]=x;
    
    
    //insert to random level
    int lvl = random_level();
    
    
    snode *newnode = new snode(value);
	newnode->rowID = rowID;
    newnode->enc2 = conv<ZZ_p>(rowID)+s;
	{
	const mie::Vuint g_temp(zToString(conv<ZZ_p>(rowID)+s));
	newnode->g1_digest = g1*g_temp;
	newnode->g2_digest = g2*g_temp;
    }
    
    
    char buf[254];
    strcpy(buf,zToString(newnode->enc2));
    
    
    
    {
        int len = 254;
        memcpy(newnode->encry, aes_encrypt(&en, (unsigned char *)buf, &len),254);
        memset(buf,0,254);
    }
    
    for(int i=0;i<lvl-1;i++){
        //link level i
        newnode->right = temp[i]->right;
        newnode->right0 = temp[i]->right0;
        temp[i]->right = NULL;
        temp[i]->right0 = newnode;
        
		compute_hash(newnode);
        
        
        
        //create up
        newnode->up = new snode(value);
        newnode->up->down = newnode;
        newnode = newnode->up;
        
    }
    
	
    
    newnode->right = temp[lvl-1]->right;
    newnode->right0 = temp[lvl-1]->right0;
    temp[lvl-1]->right = newnode;
    temp[lvl-1]->right0 = newnode;
    compute_hash(newnode);
    
	//update hashes along search path
	
	for(int i=path_node.size()-1;i>=0;i--){
		compute_hash(path_node[i]);
	}
	
	
    //update enc and bilinear
    
    for(int i=lvl;i<MAX_LEVEL;i++){
	
	
        temp[i]->enc2*=conv<ZZ_p>(rowID)+s;
        int len = 254;
        ZZ_p temp_de;
        temp_de = StringToz((char *)aes_decrypt(&de, temp[i]->encry, &len));
        strcpy(buf,zToString(temp_de*(conv<ZZ_p>(rowID)+s)));
        len = 254;
        memcpy(temp[i]->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
        memset(buf,0,254);
		{
		const mie::Vuint g_temp(zToString(temp_de*(conv<ZZ_p>(rowID)+s)));
		temp[i]->g1_digest = g1*g_temp;
		temp[i]->g2_digest = g2*g_temp;
		}
        
    }
    
    
    
    
    for(int j=0;j<lvl-1;j++){
        newnode = newnode->down;
    }
    for(int i=1;i<lvl;i++){
        newnode = newnode->up;
        ZZ_p temp_enc = conv<ZZ_p>(1);
        snode* temp_newnode = newnode->down;
        while(temp_newnode!=NULL){
            int len = 254;
            temp_enc*=StringToz((char *)aes_decrypt(&de, temp_newnode->encry, &len));
            
            
            
            temp_newnode = temp_newnode->right;
        }
        newnode->enc2 = temp_enc;
        strcpy(buf, zToString(temp_enc));
        {
            int len = 254;
            memcpy(newnode->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
            memset(buf,0,254);
        }
		
		{
		const mie::Vuint g_temp(zToString(temp_enc));
		newnode->g1_digest = g1*g_temp;
		newnode->g2_digest = g2*g_temp;
		}
        
        
        temp_enc = conv<ZZ_p>(1);
        temp_newnode = temp[i]->down;
        while(temp_newnode!=NULL){
            int len = 254;
            temp_enc*=StringToz((char *)aes_decrypt(&de, temp_newnode->encry, &len));
            temp_newnode = temp_newnode->right;
        }
        temp[i]->enc2 = temp_enc;
        strcpy(buf, zToString(temp_enc));
        {
            int len = 254;
            memcpy(temp[i]->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
            memset(buf,0,254);
        }
		
		{
		const mie::Vuint g_temp(zToString(temp_enc));
		temp[i]->g1_digest = g1*g_temp;
		temp[i]->g2_digest = g2*g_temp;
		}
    }
    
    
    return;
    
}

//construct from table

void skiplist::insert_element_inorder(int value, int rowID, ZZ_p s, Ec1 g1, Ec2 g2)
{
    snode *x = header;
    if(skiplist::contains(value)){
        cout<<"element in the list.\n";
        return;
    }
    
    //find insert points
    
    std::vector<snode*> temp(MAX_LEVEL);
	vector<snode*> path_node;
	path_node.push_back(x);
    
    for(int i=MAX_LEVEL-1;i>0;i--){
        while (x->right != NULL && x->right->value <= value)
        {
            x = x->right;
			path_node.push_back(x);
        }
        temp[i]=x;
        x=x->down;
		path_node.push_back(x);
    }
    while (x->right != NULL && x->right->value < value)
    {
        x = x->right;
		path_node.push_back(x);
    }
    temp[0]=x;
    
    
    //insert to random level
    int lvl = random_level();
    
    
    snode *newnode = new snode(value);
	newnode->rowID = rowID;
    newnode->enc2 = conv<ZZ_p>(rowID)+s;
	{
	const mie::Vuint g_temp(zToString(conv<ZZ_p>(rowID)+s));
	newnode->g1_digest = g1*g_temp;
	newnode->g2_digest = g2*g_temp;
    }
    
    
    char buf[254];
    strcpy(buf,zToString(newnode->enc2));
    
    
    
    {
        int len = 254;
        memcpy(newnode->encry, aes_encrypt(&en, (unsigned char *)buf, &len),254);
        memset(buf,0,254);
    }
    
    for(int i=0;i<lvl-1;i++){
        //link level i
        newnode->right = temp[i]->right;
        newnode->right0 = temp[i]->right0;
        temp[i]->right = NULL;
        temp[i]->right0 = newnode;
        
		compute_hash(newnode);
        
        
        
        //create up
        newnode->up = new snode(value);
        newnode->up->down = newnode;
        newnode = newnode->up;
        
    }
    
	
    
    newnode->right = temp[lvl-1]->right;
    newnode->right0 = temp[lvl-1]->right0;
    temp[lvl-1]->right = newnode;
    temp[lvl-1]->right0 = newnode;
    compute_hash(newnode);
    
	//update hashes along search path
	
	for(int i=path_node.size()-1;i>=0;i--){
		compute_hash(path_node[i]);
	}
	
	
    //update enc and bilinear
    
	/*
    for(int i=lvl;i<MAX_LEVEL;i++){
	
	
        temp[i]->enc2*=conv<ZZ_p>(rowID)+s;
        int len = 254;
        ZZ_p temp_de;
        temp_de = StringToz((char *)aes_decrypt(&de, temp[i]->encry, &len));
        strcpy(buf,zToString(temp_de*(conv<ZZ_p>(rowID)+s)));
        len = 254;
        memcpy(temp[i]->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
        memset(buf,0,254);
		{
		const mie::Vuint g_temp(zToString(temp_de*(conv<ZZ_p>(rowID)+s)));
		temp[i]->g1_digest = g1*g_temp;
		temp[i]->g2_digest = g2*g_temp;
		}
        
    }
    */
    
    
    
    for(int j=0;j<lvl-1;j++){
        newnode = newnode->down;
    }
    for(int i=1;i<lvl;i++){
        newnode = newnode->up;
        ZZ_p temp_enc = conv<ZZ_p>(1);
        snode* temp_newnode = newnode->down;
        while(temp_newnode!=NULL){
            int len = 254;
            temp_enc*=StringToz((char *)aes_decrypt(&de, temp_newnode->encry, &len));
            
            
            
            temp_newnode = temp_newnode->right;
        }
        newnode->enc2 = temp_enc;
        strcpy(buf, zToString(temp_enc));
        {
            int len = 254;
            memcpy(newnode->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
            memset(buf,0,254);
        }
		
		{
		const mie::Vuint g_temp(zToString(temp_enc));
		newnode->g1_digest = g1*g_temp;
		newnode->g2_digest = g2*g_temp;
		}
        
        /*
        temp_enc = conv<ZZ_p>(1);
        temp_newnode = temp[i]->down;
        while(temp_newnode!=NULL){
            int len = 254;
            temp_enc*=StringToz((char *)aes_decrypt(&de, temp_newnode->encry, &len));
            temp_newnode = temp_newnode->right;
        }
        temp[i]->enc2 = temp_enc;
        strcpy(buf, zToString(temp_enc));
        {
            int len = 254;
            memcpy(temp[i]->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
            memset(buf,0,254);
        }
		
		{
		const mie::Vuint g_temp(zToString(temp_enc));
		temp[i]->g1_digest = g1*g_temp;
		temp[i]->g2_digest = g2*g_temp;
		}
		*/
    }
    
    
    return;
    
}


// insert inverse value

void skiplist::insert_element_inverse_inorder(int value, int rowID, ZZ_p s, Ec1 g1, Ec2 g2)
{
    snode *x = header;
    if(skiplist::contains(value)){
        cout<<"element in the list.\n";
        return;
    }
    
    //find insert points
    
    std::vector<snode*> temp(MAX_LEVEL);
	vector<snode*> path_node;
	path_node.push_back(x);
    
    for(int i=MAX_LEVEL-1;i>0;i--){
        while (x->right != NULL && x->right->value <= value)
        {
            x = x->right;
			path_node.push_back(x);
        }
        temp[i]=x;
        x=x->down;
		path_node.push_back(x);
    }
    while (x->right != NULL && x->right->value < value)
    {
        x = x->right;
		path_node.push_back(x);
    }
    temp[0]=x;
    
    
    //insert to random level
    int lvl = random_level();
    
    
    snode *newnode = new snode(value);
	newnode->rowID = rowID;
    newnode->enc2 = 1/conv<ZZ_p>(rowID)+s;
	{
	const mie::Vuint g_temp(zToString(1/conv<ZZ_p>(rowID)+s));
	newnode->g1_digest = g1*g_temp;
	newnode->g2_digest = g2*g_temp;
    }
    
    
    char buf[254];
    strcpy(buf,zToString(newnode->enc2));
    
    
    
    {
        int len = 254;
        memcpy(newnode->encry, aes_encrypt(&en, (unsigned char *)buf, &len),254);
        memset(buf,0,254);
    }
    
    for(int i=0;i<lvl-1;i++){
        //link level i
        newnode->right = temp[i]->right;
        newnode->right0 = temp[i]->right0;
        temp[i]->right = NULL;
        temp[i]->right0 = newnode;
        
		compute_hash(newnode);
        
        
        
        //create up
        newnode->up = new snode(value);
        newnode->up->down = newnode;
        newnode = newnode->up;
        
    }
    
	
    
    newnode->right = temp[lvl-1]->right;
    newnode->right0 = temp[lvl-1]->right0;
    temp[lvl-1]->right = newnode;
    temp[lvl-1]->right0 = newnode;
    compute_hash(newnode);
    
	//update hashes along search path
	
	for(int i=path_node.size()-1;i>=0;i--){
		compute_hash(path_node[i]);
	}
    
    
    
    //update enc and bilinear
  /*  
    for(int i=lvl;i<MAX_LEVEL;i++){
        temp[i]->enc2*=1/conv<ZZ_p>(rowID)+s;
        int len = 254;
        ZZ_p temp_de;
        temp_de = StringToz((char *)aes_decrypt(&de, temp[i]->encry, &len));
        strcpy(buf,zToString(temp_de*(1/conv<ZZ_p>(rowID)+s)));
        len = 254;
        memcpy(temp[i]->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
        memset(buf,0,254);
		{
		const mie::Vuint g_temp(zToString(temp_de*(1/conv<ZZ_p>(rowID)+s)));
		temp[i]->g1_digest = g1*g_temp;
		temp[i]->g2_digest = g2*g_temp;
		}
        
    }
   */
    
    
    
    for(int j=0;j<lvl-1;j++){
        newnode = newnode->down;
    }
    for(int i=1;i<lvl;i++){
        newnode = newnode->up;
        ZZ_p temp_enc = conv<ZZ_p>(1);
        snode* temp_newnode = newnode->down;
        while(temp_newnode!=NULL){
            int len = 254;
            temp_enc*=StringToz((char *)aes_decrypt(&de, temp_newnode->encry, &len));
            
            
            
            temp_newnode = temp_newnode->right;
        }
        newnode->enc2 = temp_enc;
        strcpy(buf, zToString(temp_enc));
        {
            int len = 254;
            memcpy(newnode->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
            memset(buf,0,254);
        }
		
		{
		const mie::Vuint g_temp(zToString(temp_enc));
		newnode->g1_digest = g1*g_temp;
		newnode->g2_digest = g2*g_temp;
		}
        
 /*       
        temp_enc = conv<ZZ_p>(1);
        temp_newnode = temp[i]->down;
        while(temp_newnode!=NULL){
            int len = 254;
            temp_enc*=StringToz((char *)aes_decrypt(&de, temp_newnode->encry, &len));
            temp_newnode = temp_newnode->right;
        }
        temp[i]->enc2 = temp_enc;
        strcpy(buf, zToString(temp_enc));
        {
            int len = 254;
            memcpy(temp[i]->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
            memset(buf,0,254);
        }
		
		{
		const mie::Vuint g_temp(zToString(temp_enc));
		temp[i]->g1_digest = g1*g_temp;
		temp[i]->g2_digest = g2*g_temp;
		}
*/
    }
    
    
    return;
    
}

void skiplist::insert_element_inverse(int value, int rowID, ZZ_p s, Ec1 g1, Ec2 g2)
{
    snode *x = header;
    if(skiplist::contains(value)){
        cout<<"element in the list.\n";
        return;
    }
    
    //find insert points
    
    std::vector<snode*> temp(MAX_LEVEL);
	vector<snode*> path_node;
	path_node.push_back(x);
    
    for(int i=MAX_LEVEL-1;i>0;i--){
        while (x->right != NULL && x->right->value <= value)
        {
            x = x->right;
			path_node.push_back(x);
        }
        temp[i]=x;
        x=x->down;
		path_node.push_back(x);
    }
    while (x->right != NULL && x->right->value < value)
    {
        x = x->right;
		path_node.push_back(x);
    }
    temp[0]=x;
    
    
    //insert to random level
    int lvl = random_level();
    
    
    snode *newnode = new snode(value);
	newnode->rowID = rowID;
    newnode->enc2 = 1/conv<ZZ_p>(rowID)+s;
	{
	const mie::Vuint g_temp(zToString(1/conv<ZZ_p>(rowID)+s));
	newnode->g1_digest = g1*g_temp;
	newnode->g2_digest = g2*g_temp;
    }
    
    
    char buf[254];
    strcpy(buf,zToString(newnode->enc2));
    
    
    
    {
        int len = 254;
        memcpy(newnode->encry, aes_encrypt(&en, (unsigned char *)buf, &len),254);
        memset(buf,0,254);
    }
    
    for(int i=0;i<lvl-1;i++){
        //link level i
        newnode->right = temp[i]->right;
        newnode->right0 = temp[i]->right0;
        temp[i]->right = NULL;
        temp[i]->right0 = newnode;
        
		compute_hash(newnode);
        
        
        
        //create up
        newnode->up = new snode(value);
        newnode->up->down = newnode;
        newnode = newnode->up;
        
    }
    
	
    
    newnode->right = temp[lvl-1]->right;
    newnode->right0 = temp[lvl-1]->right0;
    temp[lvl-1]->right = newnode;
    temp[lvl-1]->right0 = newnode;
    compute_hash(newnode);
    
	//update hashes along search path
	
	for(int i=path_node.size()-1;i>=0;i--){
		compute_hash(path_node[i]);
	}
    
    
    
    //update enc and bilinear
    
    for(int i=lvl;i<MAX_LEVEL;i++){
        temp[i]->enc2*=1/conv<ZZ_p>(rowID)+s;
        int len = 254;
        ZZ_p temp_de;
        temp_de = StringToz((char *)aes_decrypt(&de, temp[i]->encry, &len));
        strcpy(buf,zToString(temp_de*(1/conv<ZZ_p>(rowID)+s)));
        len = 254;
        memcpy(temp[i]->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
        memset(buf,0,254);
		{
		const mie::Vuint g_temp(zToString(temp_de*(1/conv<ZZ_p>(rowID)+s)));
		temp[i]->g1_digest = g1*g_temp;
		temp[i]->g2_digest = g2*g_temp;
		}
        
    }
    
    
    
    
    for(int j=0;j<lvl-1;j++){
        newnode = newnode->down;
    }
    for(int i=1;i<lvl;i++){
        newnode = newnode->up;
        ZZ_p temp_enc = conv<ZZ_p>(1);
        snode* temp_newnode = newnode->down;
        while(temp_newnode!=NULL){
            int len = 254;
            temp_enc*=StringToz((char *)aes_decrypt(&de, temp_newnode->encry, &len));
            
            
            
            temp_newnode = temp_newnode->right;
        }
        newnode->enc2 = temp_enc;
        strcpy(buf, zToString(temp_enc));
        {
            int len = 254;
            memcpy(newnode->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
            memset(buf,0,254);
        }
		
		{
		const mie::Vuint g_temp(zToString(temp_enc));
		newnode->g1_digest = g1*g_temp;
		newnode->g2_digest = g2*g_temp;
		}
        
        
        temp_enc = conv<ZZ_p>(1);
        temp_newnode = temp[i]->down;
        while(temp_newnode!=NULL){
            int len = 254;
            temp_enc*=StringToz((char *)aes_decrypt(&de, temp_newnode->encry, &len));
            temp_newnode = temp_newnode->right;
        }
        temp[i]->enc2 = temp_enc;
        strcpy(buf, zToString(temp_enc));
        {
            int len = 254;
            memcpy(temp[i]->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
            memset(buf,0,254);
        }
		
		{
		const mie::Vuint g_temp(zToString(temp_enc));
		temp[i]->g1_digest = g1*g_temp;
		temp[i]->g2_digest = g2*g_temp;
		}
    }
    
    
    return;
    
}

/*
 * Delete Element from Skip List
 */


void skiplist::delete_element(int value, Ec1 g1, Ec2 g2)
{
    if(!skiplist::contains(value)){
        cout<<"element not in the list.\n";
        return;
    }
    
    //find delete points
    snode *x = header;
    std::vector<snode*> temp(MAX_LEVEL);
    int lvl=0;
    
    for(int i=MAX_LEVEL-1;i>0;i--){
        while (x->right != NULL && x->right->value < value)
        {
            x = x->right;
        }
        if(x->right!=NULL && x->right->value == value){
            lvl = i;
            break;
        }
        temp[i]=x;
        x=x->down;
    }
    
    ZZ_p delete_value;
    
    //delete link
    if(lvl == 0){
        while(x->right->value != value){
            x = x->right;
        }
        temp[0] = x;
        snode* deletenode = x->right;
        temp[0]->right = deletenode->right;
        temp[0]->right0 = deletenode->right0;
        int len=254;
        delete_value = StringToz((char *)aes_decrypt(&de, deletenode->encry, &len));
        delete deletenode;
        
    }
    
    else{
        temp[lvl] = x;
        snode* deletenode = x->right;
        temp[lvl]->right = deletenode->right;
        temp[lvl]->right0 = deletenode->right0;
        delete deletenode;
        for(int i=lvl;i>=1;i--){
            snode* deletenode;
            x = temp[i]->down;
            while(1){
                if(x->right!=NULL){
                    if(x->right->value==value){
                        deletenode = x->right;
                        break;
                    }
                    else{
                        x=x->right;
                        continue;
                    }
                }
                else{
                    if(x->right0->value == value){
                        deletenode = x->right0;
                        break;
                    }
                    else{
                        x=x->right0;
                        continue;
                    }
                }
            }
            temp[i-1] = x;
            
            temp[i-1]->right = deletenode->right;
            temp[i-1]->right0 = deletenode->right0;
            if(i==1){
                int len=254;
                delete_value = StringToz((char *)aes_decrypt(&de, deletenode->encry, &len));
            }
            
            delete deletenode;
            
        }
    }
    
    //compute value
    char buf[254];
    for(int i=1;i<=lvl;i++){
        ZZ_p temp_enc = conv<ZZ_p>(1);
        snode* temp_newnode = temp[i]->down;
        while(temp_newnode!=NULL){
            int len = 254;
            temp_enc*=StringToz((char *)aes_decrypt(&de, temp_newnode->encry, &len));
            temp_newnode = temp_newnode->right;
        }
        temp[i]->enc2 = temp_enc;
        strcpy(buf,zToString(temp_enc));
        {
            int len = 254;
            memcpy(temp[i]->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
            memset(buf,0,254);
        }
		{
		const mie::Vuint g_temp(zToString(temp_enc));
		temp[i]->g1_digest = g1*g_temp;
		temp[i]->g2_digest = g2*g_temp;
		}
        
        
    }
    
    for(int i=lvl+1;i<MAX_LEVEL;i++){
        temp[i]->enc2/=delete_value;
        int len = 254;
        ZZ_p temp_de;
        temp_de = StringToz((char *)aes_decrypt(&de, temp[i]->encry, &len));
        strcpy(buf,zToString(temp_de/delete_value));
        len = 254;
        memcpy(temp[i]->encry , aes_encrypt(&en, (unsigned char *)buf, &len),254);
        memset(buf,0,254);
		{
		const mie::Vuint g_temp(zToString(temp_de/delete_value));
		temp[i]->g1_digest = g1*g_temp;
		temp[i]->g2_digest = g2*g_temp;
		}
    }
    return;
    
    
}




void skiplist::display()
{
    char* temp;
    //int len = 254;
    snode *x;
    for(int i = MAX_LEVEL-1;i>=0;i--){
        x = header;
        for(int j=0; j< MAX_LEVEL-1-i;j++){
            x = x->down;
        }
        while(x->right!=NULL || x->right0 != NULL){
            int len = 254;
            temp = (char *)aes_decrypt(&de, x->encry, &len);
            cout << x->value<<"("<<x->rowID<<")";//<<"("<<(x->enc2==StringToz(temp))<<")";
            
            //free(temp);
            if(x->right !=NULL){
                cout << " - ";
                x = x->right;
            }
            else{
                cout << "   ";
                x = x->right0;
                
            }
        }
        {
            
            int len = 254;
            temp = (char *)aes_decrypt(&de, x->encry, &len);
            cout << x->value<<"("<<x->rowID<<")";//<<"("<<(x->enc2==StringToz(temp))<<")";
        }
        
        //free(temp);
        
        cout << endl;
    }
}


/*
 * Search Elements in Skip List
 */
bool skiplist::contains(int value)
{
    snode *x = header;
    for(int i=0;i<MAX_LEVEL-1;i++){
        while (x->right != NULL && x->right->value <= value)
        {
            x = x->right;
        }
        x=x->down;
    }
    if(x->value == value)
        return true;
    while (x->right != NULL && x->right->value < value)
    {
        x = x->right;
    }
    x = x->right;
    return x != NULL && x->value == value;
    
}


vector<snode> skiplist::range_search(int value_s, int value_e){
    vector<snode*> start(MAX_LEVEL), end(MAX_LEVEL);
    int index_s=-1,index_e=-1;
    snode *node_s=NULL,*node_e=NULL;
    vector<snode> result;
    //cout<<"start:"<<value_s<<" end:"<<value_e<<"\n";
    
    //find ranges
    snode *x = header,*y = header;
    
    for(int i=MAX_LEVEL-1;i>0;i--){
        while (x->right != NULL && x->right->value < value_s)
        {
            x = x->right;
        }
        start[i]=x;
        x=x->down;
        
        while (y->right != NULL && y->right->value <= value_e)
        {
            y = y->right;
        }
        end[i]=y;
        y=y->down;
        
    }
    while (x->right != NULL && x->right->value < value_s)
    {
        x = x->right;
    }
    start[0]=x;
    while (y->right != NULL && y->right->value <= value_e)
    {
        y = y->right;
    }
    end[0]=y;
    if(y->right0!=NULL&&y->right0->value==value_e)
        end[0]=y->right0;
    
    //for(int i=0;i<MAX_LEVEL;i++)
    //    cout<<start[i]->value<<" - ";
   // cout<<"\n";
    //for(int i=0;i<MAX_LEVEL;i++)
    //    cout<<end[i]->value<<" - ";
    //cout<<"\n";
    
    //generate result
    int count = 0;
    snode* index;
    index = start[MAX_LEVEL-1];
    
    
    
    for(int i=MAX_LEVEL-1;i>=0;i--){
        count = 0;
        //cout<<"index: "<<index_s<<","<<index_e<<"\n";
        
        if(index_e>=0){
            if(node_s!=NULL){
                node_s = node_s->down;
                if(node_s->value>result[index_s].down->value)
                    node_s = result[index_s].down;
            }
            else
                node_s = result[index_s].down;
            if(node_e!=NULL){
                node_e=node_e->down;
                if(node_e->value<result[index_e].down->value)
                    node_e = result[index_e].down;
            }
            else
                node_e = result[index_e].down;
            
            while(node_e->right!=NULL)
                node_e = node_e->right;
            
            //cout<<"boundary:"<<node_s->value<<"\t"<<node_e->value<<"\n";
        }
        index = start[i];
        
        while(1){
            
            if(index->right!=NULL){
                index=index->right;
            }
            else if(index->right0!=NULL)
                index = index->right0;
            else
                break;
            
            if(index->value>=end[i]->value)
                break;
            
            if(index_e>=0){
                if(index->value==node_s->value){
                    index = node_e;
                    continue;
                }
            }
            snode result_node(index->value);
			result_node.rowID = index->rowID;
            result_node.enc2 = index->enc2;
            memcpy(result_node.encry, index->encry,254);
            result_node.down = index->down;
			result_node.g1_digest = index->g1_digest;
			result_node.g2_digest = index->g2_digest;
            result.push_back(result_node);
            //cout<<result_node.value<<"\n";
            count++;
            
            
        }
        
        
        if(count>0){
            index_s = index_e+1;
            index_e+=count;
        }
        
    }
    snode result_node(end[0]->value);
	result_node.rowID = end[0]->rowID;
    result_node.enc2 = end[0]->enc2;
    memcpy(result_node.encry, end[0]->encry,254);
	result_node.g1_digest = end[0]->g1_digest;
	result_node.g2_digest = end[0]->g2_digest;
    result.push_back(result_node);
    //cout<<result_node.value<<"\n";
    //cout<<"size:"<<result.size()<<"\n";
    
    /*test:**********
    ZZ_p test = conv<ZZ_p>(1);
    ZZ_p test2 = conv<ZZ_p>(1);
    for(int i=0;i<result.size();i++)
        test*=result[i].enc2;
    
    snode *x1 = header;
    for(int i=0;i<MAX_LEVEL-1;i++){
        while (x1->right != NULL && x1->right->value <= value_s)
        {
            x1 = x1->right;
        }
        x1=x1->down;
    }
    if(x1->value == value_s){
        
    }
 
    else{
        while (x1->right != NULL && x1->right->value < value_s)
        {
            x1 = x1->right;
        }
        x1 = x1->right;
    }
    while(x1->value <= value_e){
        test2*=x1->enc2;
        if(x1->right!=NULL){
            x1=x1->right;
        }
        else
            x1=x1->right0;
    }
    
    cout<<(test==test2)<<"!!!\n";
    */
	
    return result;
}

vector<int> skiplist::range_cover(snode* ancestor){
	std::list<snode*> temp;
	snode* current;
	temp.push_back(ancestor);
	while(temp.front()->down!=NULL){
		int size = temp.size();
		for(int i=0;i<size;i++){
			current = temp.front()->down;
			temp.pop_front();
			while(current!=NULL){
				temp.push_back(current);
				current = current->right;
			}
		}
	}
	int size = temp.size();
	vector<int> result;
	for(int i=0;i<size;i++){
		result.push_back(temp.front()->rowID);
		temp.pop_front();
	}
	
	
	
	return result;
}

vector<proofnode> skiplist::prove_path(int value){
	snode *x = header;
    vector<proofnode> proof;
    proofnode temp;
	
    for(int i=MAX_LEVEL-1;i>0;i--){

        while (x->right != NULL && x->right->value <= value)
        {
            memcpy(temp.f,x->down->hash,32);
            temp.flag = 2;
            proof.push_back(temp);
            x = x->right;
        }

        if(x->right!=NULL){
            memcpy(temp.f,x->right->hash,32);
            temp.flag = 2;
			proof.push_back(temp);
        }
        else{
            temp.flag = 0;
            proof.push_back(temp);
        }
        
        x=x->down;
    }
    
    
    
    while (x->right != NULL)
    {
        temp.v = x->value;
        temp.flag = 1;
        proof.push_back(temp);
        x = x->right;
    }

    temp.v = x->value;
    temp.flag = 1;
	proof.push_back(temp);
	
    if(x->right0!=NULL){
       temp.v = x->right0->value;
       temp.flag = 1;
	   proof.push_back(temp);

    }
    else{
        temp.flag = 0;
		proof.push_back(temp);
	}

    return proof;
}
