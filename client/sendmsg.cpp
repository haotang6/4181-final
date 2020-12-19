#include <iostream>
#include <cstdio>
#include <string>
#include <fstream>
#include <unordered_map>

using namespace std;

const string cert_path = "cindy.cert.pem";
const string key_path = "cindy.key.pem";
const string id_path = "recipient_id.txt";

/*
parameter:  username: recipient name
            message_file = sender_cert + message
            idmap: the ID (number) of the mail for the recipient
output: 3 files:  key.bin.enc - the key used for symmetric encryption
                  id_mail.enc - [id|encrypt(sender_cert, msg)]
                  signature.sign - the signature
*/
void generate_message(string username, string message_file, unordered_map<string, int>& idmap) {
    
    // get pub key and use the pub key to encrypt the key for symmetric encryption
    system(("openssl x509 -pubkey -noout -in " + username + ".cert.pem > temp.pubkey.pem").c_str());
    system("openssl rand -base64 32 > key.bin");
    system("openssl rsautl -encrypt -pubin -inkey temp.pubkey.pem -in key.bin -out key.bin.enc");
    
    // use symmetric encryption to encrypt the file
    system(("openssl enc -pbkdf2 -salt -in " + message_file
            + " -out temp.enc -pass file:./key.bin").c_str());

    // add id before
    if (!idmap.count(username)) idmap[username] = 0;
    ofstream out("id_mail.enc", ofstream::binary);
    ifstream message("temp.enc", ifstream::binary);
    out << ++idmap[username] << endl << message.rdbuf() << endl;
    message.close();
    out.close();

    // sign the [id|encrypt(sender_cert, msg)]
    system(("openssl dgst -sha256 -sign " + key_path + " -out signature.sign id_mail.enc").c_str());

    // clear intermediate file    
    system("rm key.bin temp.enc temp.pubkey.pem");
}

int main(){
    // get the mail-id for each recipient
    ifstream idfile(id_path.c_str(), ifstream::binary);
    unordered_map<string, int> idmap;
    string recipient;
    int num;
    while(idfile >> recipient >> num){
        idmap[recipient] = num;
    }
    idfile.close();

    // generate [cert|msg]
    ofstream out("testMessage.txt", ofstream::binary);
    ifstream cert(cert_path, ifstream::binary);
    ifstream msg("MessageText.txt", ifstream::binary);
    out << cert.rdbuf() << endl << msg.rdbuf();
    msg.close();
    cert.close();
    out.close();

    // to be done: get recipients' cert and save to the disk as "user.cert.pem"
    generate_message("bob", "testMessage.txt", idmap);

    system("rm -rf testMessage.txt");
    
    // update the id file
    ofstream idfile2(id_path.c_str(), ofstream::binary);
    for(auto &p: idmap){
        idfile2 << p.first << " " << p.second << endl;
    }
    idfile2.close();
}