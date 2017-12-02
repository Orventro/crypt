#include <string>
#include <fstream>
#include <cmath>

using namespace std;

char toChr(char n){
    if(n < 10) return '0' + n;
    else return 'A' + n - 10;
}

string toStr(unsigned long long n, int base){
    string s;
    while(n > 0){
        s = toChr(n%base) + s;
        n /= base;
    }
    return s;
}

unsigned long long swap(unsigned long long n, unsigned char operation, unsigned char p1, unsigned char p2){
    if(p1 == p2) return n;
    unsigned long long n1, n2, bits, max;
    bits = operation%4+1;
    p1 *= bits;
    p2 *= bits;
    max = 1<<bits;
    n1 = (n >> p1) % max;
    n2 = (n >> p2) % max;
    n -= (n1 << p1) + (n2 << p2);
    if(operation/4 == 0)      return n + (n1      << p2) + (n2           << p1);
    else if(operation/4 == 1) return n + (~n1%max << p2) + (~n2%max      << p1);
    else if(operation/4 == 2) return n + (n1      << p2) + ((n2^n1)      << p1);
    else                      return n + (~n1%max << p2) + (~(n2^n1)%max << p1);
}

unsigned long long unswap(unsigned long long n, unsigned char operation, unsigned char p1, unsigned char p2){
    if(p1 == p2) return n;
    unsigned long long n1, n2, bits, max;
    bits = operation%4+1;
    p1 *= bits;
    p2 *= bits;
    max = 1<<bits;
    n1 = (n >> p1) % max;
    n2 = (n >> p2) % max;
    n -= (n1 << p1) + (n2 << p2);
    if(operation/4 == 0)      return n + (n1      << p2) + (n2      << p1);
    else if(operation/4 == 1) return n + (~n1%max << p2) + (~n2%max << p1);
    else if(operation/4 == 2) return n + ((n2^n1) << p2) + (n2      << p1);
    else                      return n + ((n2^n1) << p2) + (~n2%max << p1);
}

// values of key < 16, minimal keysize is 3, otherwise data may be corrupted
unsigned long long encrypt(unsigned long long n, unsigned char *key, unsigned int keysize, unsigned int keystart){
    for(int i = keystart; i < keysize+keystart; i++)
        n = swap(n, key[i%keysize], key[(i+1)%keysize], key[(i+2)%keysize]);
    return n;
}

// values of key < 16, minimal keysize is 3, otherwise data may be corrupted
unsigned long long decrypt(unsigned long long n, unsigned char *key, unsigned int keysize, unsigned int keystart){
    for(int i = keysize+keystart-1; i >= (int)keystart; i--){
        n = unswap(n, key[i%keysize], key[(i+1)%keysize], key[(i+2)%keysize]);
    }
    return n;
}

void encrypt(unsigned long long *n, unsigned int nsize, unsigned char *key, unsigned int keysize){
    for(int i = 0; i < nsize; i++)
        n[i] = encrypt(n[i], key, keysize, i);
}

void decrypt(unsigned long long *n, unsigned int nsize, unsigned char *key, unsigned int keysize){
    for(int i = 0; i < nsize; i++)
        n[i] = decrypt(n[i], key, keysize, i);
}

unsigned char* toKey(char *arr, unsigned int keysize){
    unsigned char *key = new unsigned char[keysize];
    for(int i = 0; i < keysize; i++){
        if     ('0' <= arr[i] & arr[i] <= '9') key[i] = arr[i] - '0';
        else if('a' <= arr[i] & arr[i] <= 'f') key[i] = arr[i] - 'a' + 10;
        else if('A' <= arr[i] & arr[i] <= 'F') key[i] = arr[i] - 'A' + 10;
    }
    return key;
}

unsigned char* toKey(string s){
    return toKey((char*)s.c_str());
}

void encrypt(string path, unsigned char * key, unsigned int keysize){
    fstream file;
    file.open((char*)path.c_str(), ios::binary|ios::in|ios::ate);
    unsigned long long s = file.tellg();
    file.seekg(0);
    unsigned long long *n = new unsigned long long[(unsigned long long)ceil(s/8.0)];
    int i=0;
    while(!file.eof()){
        file.read((char*)&(n[i]), sizeof n[i]);
        i++;
    }
    file.close();
    encrypt(n, ceil(s/8.0), key, keysize);
    file.open((char*)(path+".encr").c_str(), ios::binary|ios::out);
    char c = s % 8;
    file.write((char*)(&c), sizeof c);
    for(int i = 0; i < ceil(s/8.0); i++){
        file.write((char*)(&n[i]), sizeof n[i]);
    }
    file.close();
    delete[] n;
}

void decrypt(string path, unsigned char * key, unsigned int keysize){
    fstream file;
    file.open((char*)path.c_str(), ios::binary|ios::in|ios::ate);
    unsigned long long s = (unsigned long long)file.tellg()-1;
    file.seekg(0);
    char c;
    file.read((char*)&c, sizeof c);
    unsigned long long *n = new unsigned long long[s/8];
    int i=0;
    while(!file.eof()){
        file.read((char*)&(n[i]), sizeof n[i]);
        i++;
    }
    file.close();
    decrypt(n, s/8, key, keysize);
    if (path.substr(path.length()-5,5)== ".encr")
        path = path.substr(0,path.length()-5);
    file.open((char*)(path+".decr").c_str(), ios::binary|ios::out);
    for(int i = 0; i < s/8-1; i++)
        file.write((char*)(&n[i]), sizeof n[i]);
    if(c == 0) 
        file.write((char*)(&n[s/8-1]), sizeof n[s/8-1]);
    char b;
    for(int i = 0; i < c; i++){
        b = n[s/8-1] >> i*8;
        file.write((char*)&b, sizeof b);
    }
    file.close();
    delete[] n;
}

int main(int argc, char *argv[]){
    unsigned char *k = toKey(argv[3], string(argv[3]).length());

    if(string(argv[1]) == "e")
        encrypt(string(argv[2]), k, string(argv[3]).length());

    else
        decrypt(string(argv[2])+".encr", k, string(argv[3]).length());

}