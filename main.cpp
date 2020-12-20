#include "iping.h"
#include <iostream>

using namespace std;
int main(int argc, char* argv[]) {
    if(argc != 2) {
        cerr<<"please give an ip or a domain name as arg"<<endl;
        return -1;
    }

    iping myping(argv[1]);
    return 0;
}
