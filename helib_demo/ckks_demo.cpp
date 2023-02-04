#include <helib/helib.h>

using namespace std;
using namespace helib;

void printVec(vector<int> v, int n){
    for(int i = 0; i < n; i ++) cout << v[i] << " ";
    cout << endl;
}
void printVec(vector<double> v, int n){
    for(int i = 0; i < n; i ++) cout << v[i] << " ";
    cout << endl;
}
int main(int argc, char* argv[])
{

    // the context is relavant to all operations. among other things it determines the number of homographic
    //operations we can perform on our encrypted  data before having to refresh 
  Context context =
      ContextBuilder<CKKS>().m(32 * 1024).bits(358).precision(20).c(6).build();

    cout << "\n\n--------------------HOMOMORPHIC ADD/MULT--------------------\n\n";
    // the number of operation we can perform before decryption is impossible  
    cout << "securityLevel=" << context.securityLevel() << "\n";

    // decryption key
    SecKey secretKey(context);
    secretKey.GenSecKey();

    const PubKey& publicKey = secretKey;
    
    // Get the number of slots, n.  Note that for CKKS, we always have n=m/4.
    long n = context.getNSlots();

    cout <<  "We want to compute 2+5 homo-morphically" << endl;
    vector<int> v0 = {};
    v0.resize(n);
    v0[0]=2; //<2,0,0,0,0...>
    printVec(v0,4);

    vector<int> v1 = {};
    v1.resize(n);
    v1[0]=5; //<5,0,0,0,0...>
    printVec(v1,4);


    //Inputs are vectors but they still have to be encoded as plaintext polynomials that we can work with in ckks
    PtxtArray p0(context,v0);
    PtxtArray p1(context,v1);


    //construct 2 cipher texts to store our plain texts
    Ctxt c0(publicKey); p0.encrypt(c0);
    Ctxt c1(publicKey); p1.encrypt(c1);

    //compute addition homo-morphically
    Ctxt c2 = c0; c2 += c1;

    //decrypt result and store to a plaintext
    PtxtArray p2(context);
    p2.decrypt(c2, secretKey);
    //decode plaintext and store to standard vector
    vector<double> v2;
    p2.store(v2);

    //print result
    printVec(v2,4);

    cout << "should observe the addition result 7 in the first slot of vector, but you'll observe the standard error that comes with approximate homo-morphic operations in the other slots. You dont get 0." << endl;

    cout << "lets compute 2 * 5" << endl;

    c2 = c0; c2 *= c1;

    //decrypt result and store to a plaintext
    p2.decrypt(c2, secretKey);
    //decode plaintext and store to standard vector
    p2.store(v2);

    cout << "result" << endl;
    //print result
    printVec(v2,4);

    cout << "\n\n--------------------DEPTH--------------------\n\n";
    cout << "the number of operations we can perform on ciphertext is limited by the parameters we choose for the context object";
    cout << "c = encrypted(<2,0,0,...>)" << endl;
    cout << "capacity is related to the number of homomorphic operations we can perform, it decreases as we perform more" << endl;
    cout << "capacity of c" << endl;
    cout << c0.capacity() << endl;
    cout << "multiplication reduces capacity faster than addition" << endl;
    cout << "capacity of c + c" << endl;
    c0 += c0;
    cout << c0.capacity() << endl;
    cout << "capacity of c^2" << endl;
    c0 *= c0;
    cout << c0.capacity() << endl;

    cout << "lets decrypt and look at error" << endl;;
    p2.decrypt(c0,secretKey);
    p2.store(v2);
    cout << "should be: " << pow(4,2) << " actual: ";
    printVec(v2,4); 


    c0 *= c0; //c^4
    c0 *= c0; //c^8
    c0 *= c0; //c^16
    c0 *= c0; //c^32
    c0 *= c0; //c^64
    c0 *= c0; //c^128
    c0 *= c0; //c^256, any further and we will be unable to encrypt due to to much noise
    cout << "capacity of c^256" << endl;
    cout << c0.capacity() << endl;
    cout << "lets decrypt and look at error" << endl;;
    p2.decrypt(c0,secretKey);
    p2.store(v2);
    cout << "should be: " << pow(4,256) << " actual: ";
    printVec(v2,4); 



}