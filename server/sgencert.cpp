#include <stdio.h>
#include <stdlib.h>
#include <string>
using namespace std;
int main() {
    string username = "georgia";
    string path_csr = "~/ca/intermediate/csr/"+username+".csr.pem";
    string command = "./sgencert.sh " + username + " " + path_csr;
    system(command.c_str());
}