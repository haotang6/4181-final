#include <iostream>
#include <cstdio>
#include <string>
#include <fstream>
#include <unordered_map>
#include <memory>
#include <stdexcept>
#include <array>

using namespace std;

const string cert_path = "bob.cert.pem";
const string key_path = "bob.key.pem";
const string id_path = "sender_id.txt";

// execute shell command and return the output
string exec(const string& cmd) {
    array<char, 128> buffer;
    string result;
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        cerr << "popen() failed!" <<endl;
        exit(1);
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

/*
parameter:  key_file: should decrypt it and then use it to decrypt msg
            id_mail.enc = [id, encrypt(cert,msg)]
            signature.sign
            sendername
            idmap
*/
void check_and_decrypt(string key_file, string id_mail_file, string sign_file, 
                       string sendername, unordered_map<string, int>& idmap) {
    
    // get key for decryption from key_file
    system(("openssl rsautl -decrypt -inkey " + key_path + 
            " -in " + key_file + " -out key.dec").c_str());

    // split the id and encrypted file
    ifstream id_mail(id_mail_file.c_str(), ifstream::binary);
    ofstream encrypted("mail.enc", ofstream::binary);
    string id;
    getline(id_mail, id);
    encrypted << id_mail.rdbuf();
    id_mail.close();
    encrypted.close();

    // check id
    if (!idmap.count(sendername)) idmap[sendername]=0;
    if (++idmap[sendername] != stoi(id)) {
        cout << "id corrupted. " << endl;
        return;
    }
    
    // decrypt file
    system("openssl enc -d -pbkdf2 -in mail.enc -out temp.dec -pass file:./key.dec");

    // split decrypted to [cert, msg]
    ifstream decrypted("temp.dec", ifstream::binary);
    ofstream cert("sender.cert.pem", ofstream::binary);
    ofstream msg("message.txt", ofstream::binary);
    string line;
    while(getline(decrypted, line)){
        if (line.size()) cert << line << endl;
        else break;
    }
    msg << decrypted.rdbuf();
    cert.close();
    decrypted.close();
    msg.close();

    // need to be done check sender's cert

    // get pub key from cert and check signiture
    system("openssl x509 -pubkey -noout -in sender.cert.pem > sender.pubkey.pem");
    if (exec("openssl dgst -sha256 -verify sender.pubkey.pem -signature " +
            sign_file + " " + id_mail_file) != "Verified OK\n") {
            cout << "Mail corrupted." << endl;
            return;
    }
}

int main(){
    // get the mail-id for each sender
    ifstream idfile(id_path.c_str(), ifstream::binary);
    unordered_map<string, int> idmap;
    string recipient;
    int num;
    while(idfile >> recipient >> num){
        idmap[recipient] = num;
    }
    idfile.close();

    // get 3 files: key.bin.enc id_mail.enc signature.sign
    check_and_decrypt("key.bin.enc", "id_mail.enc", "signature.sign", "Cindy", idmap);

    // update the id file
    ofstream idfile2(id_path.c_str(), ofstream::binary);
    for(auto &p: idmap){
        idfile2 << p.first << " " << p.second << endl;
    }
    idfile2.close();
}