#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <vector>

using namespace std;

extern int errno;

unsigned char k3[17] = "Information Sec";
unsigned char iv[17];

unsigned char encriptedVect[16]; //encrypted key
unsigned char decriptedVect[16]; // the decripted key
unsigned char encriptInitVector[16];

char mesajMod[50];                  // cfb sau ecb?
unsigned char mesajeTransmise[100]; // alte mesaje trimise intre noduri

void A() // functia de decriptare a cheii
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    int outlen;
    /*
    EVP_DecryptInit(ctx, EVP_aes_128_cfb(), k3, iv);
    EVP_DecryptUpdate(ctx, decriptedVect, &outlen, encriptedVect, sizeof(encriptedVect)); */

    if (strcmp(mesajMod, "ECB") == 0 || strcmp(mesajMod, "ecb") == 0)
    {
        EVP_DecryptInit(ctx, EVP_aes_128_ecb(), k3, iv);
        EVP_DecryptUpdate(ctx, decriptedVect, &outlen, encriptedVect, sizeof(encriptedVect));
    }
    if (strcmp(mesajMod, "CFB") == 0 || strcmp(mesajMod, "cfb") == 0)
    {
        EVP_DecryptInit(ctx, EVP_aes_128_cfb(), k3, iv);
        EVP_DecryptUpdate(ctx, decriptedVect, &outlen, encriptedVect, sizeof(encriptedVect));
    }

    EVP_CIPHER_CTX_free(ctx);
}

char mesajConfirmareInceput[16];
unsigned char encriptedCaractersBlock[128]; //encrypted block of chars
//unsigned char decriptedBlock[16]; //the decrypted block of chars
unsigned char vectorDeCaractere[128]; //blocul de caractere citit din fisier
string line;
char mesajConfirmareCitire[100]="start";

int main(int argc, char *argv[])
{
    if (argc != 3) // daca nu este structura buna la input
    {
        printf("Sintaxa: %s <adresa_server> <port>\n", argv[0]);
        return -1;
    }
    struct sockaddr_in server;

    int sd; // socket descriptor
    if ((sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
        perror("Eroare la socket().\n");
        return errno;
    }

    int opt = 1; //
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt));

    server.sin_family = AF_INET;
    server.sin_port = htons(atoi(argv[2]));
    server.sin_addr.s_addr = inet_addr(argv[1]);

    if (connect(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
    {
        perror("[client]Eroare la connect().\n");
        return errno;
    }

    while (1)
    {
        cout << "Alege ECB / CFB: ";
        cin >> mesajMod;
        if (strcmp(mesajMod, "ECB") == 0 || strcmp(mesajMod, "CFB") == 0 || strcmp(mesajMod, "ecb") == 0 || strcmp(mesajMod, "cfb") == 0)
            break;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    int outlen;

    send(sd, &mesajMod, 50, 0); //trimite la KM modul ales de A

    recv(sd, &mesajMod, 100, 0); //primeste modul de operarea de la  KM

    recv(sd, &encriptedVect, 100, 0); //primeste encripted key de la  KM

    recv(sd, &iv, 100, 0); //primeste iv de la  KM
    cout << "Am prmit iv de la km " << iv<<endl;

    A(); //decripteaza cheia

    memcpy(mesajeTransmise, "send", 4); // mesajul, trimis catre KM de ready

    unsigned char encriptedMesaj[100]; //cripaterea mesajului de ready

    if (strcmp(mesajMod, "ECB") == 0 || strcmp(mesajMod, "ecb") == 0)
    {
        EVP_EncryptInit(ctx, EVP_aes_128_ecb(), decriptedVect, iv); // criptam mesajul de ready
        EVP_EncryptUpdate(ctx, encriptedMesaj, &outlen, mesajeTransmise, sizeof(mesajeTransmise));
        send(sd, &encriptedMesaj, 100, 0); //trimite mesajul de ready
    }
    else
    {
        EVP_EncryptInit(ctx, EVP_aes_128_cfb(), decriptedVect, iv); //criptam mesajul de ready
        EVP_EncryptUpdate(ctx, encriptedMesaj, &outlen, mesajeTransmise, sizeof(mesajeTransmise));
        send(sd, &encriptedMesaj, 100, 0); //trimite mesajul de ready
    }
    recv(sd,&mesajConfirmareInceput,100,0);
    cout<<"Am primit mesjaul de confrmare "<<mesajConfirmareInceput<<endl;

    ifstream fin("text.txt");


      
    /*fin>>vectorDeCaractere;
    if (strcmp(mesajMod, "ECB") == 0 || strcmp(mesajMod, "ecb") == 0)
                {
                    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), decriptedVect, iv); // criptam mesjaul de ready
                    EVP_EncryptUpdate(ctx, encriptedCaractersBlock, &outlen, vectorDeCaractere, sizeof(vectorDeCaractere));
                    //cout<<"Inainte de criptare am trimis: "<<vectorDeCaractere<<endl;
                    send(sd, &encriptedCaractersBlock, 100, 0); //trimite la KM blocul de date criptat
                    //cout<<"Am trimis:  "<<encriptedCaractersBlock<<endl;
                }
                else
                {
                    EVP_EncryptInit(ctx, EVP_aes_128_cfb(), decriptedVect, iv); //criptam mesajul de ready
                    EVP_EncryptUpdate(ctx, encriptedCaractersBlock, &outlen, vectorDeCaractere, sizeof(vectorDeCaractere));
                    send(sd, &encriptedCaractersBlock, 100, 0); //trimite la KM blocul de date criptat
                    //cout<<"Inainte de criptare am trimis: "<<vectorDeCaractere<<endl;
                    //cout<<"Am trimis :"<<encriptedCaractersBlock<<endl;
                }
                EVP_CIPHER_CTX_free(ctx);*/

    while (getline(fin, line)) //cat timp mai avem ce citi
    {

        cout<<"E ok .Intra in while.";
        getline(fin, line); //citeste din fin cate o linie si o pune in line

        send(sd,&mesajConfirmareCitire,100,0);//mesaj in care zicem ca mai avem caractere in fisier
        //send(sd,&mesajConfirmareCitire,100,0);//mesaj in care zicem ca mai avem caractere in fisier

        int j = 0;
        for (int i = 0; i <= line.size(); i++)
        {   
            vectorDeCaractere[j] = line[i]; // punem in bloc, caracter cu caracter
            j++;                            // contorizam caracterele adaugate

            if (j == 16) // daca avem un bloc de 16 caractere
            {
                vectorDeCaractere[j] = '\0'; //golim vectorul de caractere
                j = 0;
                                       //resetam contorul
                cout<<vectorDeCaractere<<endl; //printam vectorul de caractere (blocul de caractere)

                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                EVP_CIPHER_CTX_init(ctx);
                int outlen;

                if (strcmp(mesajMod, "ECB") == 0 || strcmp(mesajMod, "ecb") == 0)
                {
                    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), decriptedVect, iv); // criptam mesjaul de ready
                    EVP_EncryptUpdate(ctx, encriptedCaractersBlock, &outlen, vectorDeCaractere, sizeof(vectorDeCaractere));
                    //cout<<"Inainte de criptare am trimis: "<<vectorDeCaractere<<endl;
                    send(sd, &encriptedCaractersBlock, 100, 0); //trimite la KM blocul de date criptat
                    //cout<<"Am trimis:  "<<encriptedCaractersBlock<<endl;
                }
                else
                {
                    EVP_EncryptInit(ctx, EVP_aes_128_cfb(), decriptedVect, iv); //criptam mesajul de ready
                    EVP_EncryptUpdate(ctx, encriptedCaractersBlock, &outlen, vectorDeCaractere, sizeof(vectorDeCaractere));
                    send(sd, &encriptedCaractersBlock, 100, 0); //trimite la KM blocul de date criptat
                    //cout<<"Inainte de criptare am trimis: "<<vectorDeCaractere<<endl;
                    //cout<<"Am trimis :"<<encriptedCaractersBlock<<endl;
                }
                EVP_CIPHER_CTX_free(ctx);
                /*
                unsigned char mesajDupaTrimitereBlocuri[100];
                
                memcpy(mesajDupaTrimitereBlocuri, "Am Trimis Blocuri", 20);

                send(sd,&mesajDupaTrimitereBlocuri,100,0); //trimiterea mesajului catre KM
                */

            }
        }
    }
    strcpy(mesajConfirmareInceput,"finish");
    send(sd,&mesajConfirmareInceput,100,0);

    fin.close();
    close(sd);
}
