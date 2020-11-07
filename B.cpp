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

using namespace std;

extern int errno;

unsigned char k3[17] = "Information Sec";
unsigned char iv[17];

unsigned char encriptedVect[16]; //encrypted key
unsigned char decriptedVect[16]; // the decripted key
unsigned char encriptInitVector[16];

 char mesajMod[50]; // cfb sau ecb?
unsigned char mesajeTransmise[100]; // alte mesaje trimise intre noduri

void B () // functia de decriptare a cheii
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    int outlen;

    if ( strcmp(mesajMod, "ECB") == 0 || strcmp(mesajMod, "ecb") == 0) {
        EVP_DecryptInit(ctx, EVP_aes_128_ecb(), k3, iv);
        EVP_DecryptUpdate(ctx, decriptedVect, &outlen, encriptedVect, sizeof(encriptedVect));
    }
    if ( strcmp(mesajMod, "CFB") == 0 || strcmp(mesajMod, "cfb") == 0) {
        EVP_DecryptInit(ctx, EVP_aes_128_cfb(), k3, iv);
        EVP_DecryptUpdate(ctx, decriptedVect, &outlen, encriptedVect, sizeof(encriptedVect));
    }

    EVP_CIPHER_CTX_free(ctx);
}

unsigned char encriptedBlock[16]; //encrypted block of chars
unsigned char decriptedBlock[16]; //the decrypted block of chars

int main (int argc, char *argv[])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    int outlen;

    if (argc != 3) // daca nu este structura buna la input
    {
        printf ("Sintaxa: %s <adresa_server> <port>\n", argv[0]);
        return -1;
    }
    struct sockaddr_in server;

    int sd;// socket descriptor
    if ((sd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
        perror ("Eroare la socket().\n");
        return errno;
    }

    int opt = 1; //
    setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, (void *) &opt, sizeof (opt));

    server.sin_family = AF_INET;
    server.sin_port = htons (atoi (argv[2]));
    server.sin_addr.s_addr = inet_addr(argv[1]);

    if (connect (sd, (struct sockaddr *) &server,sizeof (struct sockaddr)) == -1)
    {
        perror ("[client]Eroare la connect().\n");
        return errno;
    }

    while(1) {
        cout << "Alege ECB / CFB: ";
        cin >> mesajMod;
        if ( strcmp(mesajMod, "ECB") == 0 || strcmp(mesajMod, "CFB") == 0 || strcmp(mesajMod, "ecb") == 0 || strcmp(mesajMod, "cfb") == 0)
            break;
    }

    send(sd,&mesajMod,50,0);//trimite la KM modul ales de A

    recv(sd, &mesajMod, 100, 0); //primeste modul de operarea de la  KM

    cout<<"Am primit modul de operare: "<<mesajMod;

    recv(sd, &encriptedVect, 100, 0); //primeste encripted key de la  KM

    recv(sd, &iv, 100, 0); //primeste iv de la  KM

    B(); //decripteaza cheia

    memcpy(mesajeTransmise, "send",4);
    unsigned char encriptedMesaj[100];
    unsigned char blocPrimitKM[100];
    unsigned char decriptBlocPrimitKM[100];
    char mesajConfirmareInceput[16];
    char mesajConfirmareCitire[100];


    if(strcmp(mesajMod,"ECB")==0 || strcmp(mesajMod,"ecb")==0)
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(ctx);
        int outlen;

        EVP_EncryptInit(ctx, EVP_aes_128_ecb(), decriptedVect, iv);
        EVP_EncryptUpdate(ctx, encriptedMesaj, &outlen, mesajeTransmise, sizeof(mesajeTransmise));

        send(sd, &encriptedMesaj, 100, 0); //trimite mesajul de ready
        recv(sd,&mesajConfirmareInceput,100,0);//primire mesaj de confirmare inceput
        cout<<"Am primit mesjaul de confrmare"<<mesajConfirmareInceput<<endl;
        cout<<"1111111111";

        while(1){
            cout<<"Am primit mesajul de ocnfirmare1: "<<mesajConfirmareCitire<<endl;

            recv(sd, &mesajConfirmareCitire, 100, 0);
            cout<<"Am primit mesajul de ocnfirmare2: "<<mesajConfirmareCitire<<endl;
            if(strcmp(mesajConfirmareCitire,"finish")==0)
                break;

            recv(sd,&blocPrimitKM,100,0);
            cout<<"Am primit blocul:"<<blocPrimitKM<<endl;

            EVP_DecryptInit(ctx, EVP_aes_128_ecb(), k3, iv); //decriptarea bloculu trimis de KM
            EVP_DecryptUpdate(ctx, decriptBlocPrimitKM, &outlen, blocPrimitKM, sizeof(blocPrimitKM));

            cout<<"Am decriptat blocul: "<<decriptBlocPrimitKM<<endl;

        }
        EVP_CIPHER_CTX_free(ctx);

        
        
    }
    else
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(ctx);
        int outlen;

        EVP_EncryptInit(ctx, EVP_aes_128_cfb(), decriptedVect, iv);
        EVP_EncryptUpdate(ctx, encriptedMesaj, &outlen, mesajeTransmise, sizeof(mesajeTransmise));

        send(sd, &encriptedMesaj, 100, 0); //trimite mesajul de ready
        recv(sd,&mesajConfirmareInceput,100,0);//primire mesaj de confirmare inceput

        cout<<"Am primit mesjaul de confrmare "<<mesajConfirmareInceput<<endl;

        while(1){
            recv(sd,&mesajConfirmareCitire,100,0);
            cout<<"Am primit mesajul de confirmare: "<<mesajConfirmareCitire<<endl;
            if(strcmp(mesajConfirmareCitire,"finish")==0)
                break;

            recv(sd,&blocPrimitKM,100,0);
            cout<<"Am primit blocul: "<<blocPrimitKM<<endl;

            EVP_DecryptInit(ctx, EVP_aes_128_ecb(), k3, iv); //decriptareea bloculu trimis de KM
            EVP_DecryptUpdate(ctx, decriptBlocPrimitKM, &outlen, blocPrimitKM, sizeof(blocPrimitKM));

            cout<<"Am decriptat blocul: "<<decriptBlocPrimitKM<<endl;

        }
        EVP_CIPHER_CTX_free(ctx);

        recv(sd,&blocPrimitKM,100,0);
        cout<<"Am primit blocul: "<<blocPrimitKM<<endl;
    }


    close (sd);
}