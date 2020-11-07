#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <iostream>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <random>

using namespace std;

#define PORT 2024
#define address "127.0.0.12"

extern int errno;

unsigned char k3[17] = "Information Sec";
unsigned char iv[16]; //OFB

unsigned char encriptedVect[16];     //encrypted key
unsigned char encriptInitVector[16]; // criptarea vectorului de intializare

char mesajMod[50];         // cfb sau ecb?
char mesajeTransmise[100]; // alte mesaje trimise intre noduri

char typeTrimis[100];

unsigned char k2[16]; //OFB
unsigned char k1[16]; // CFB

void KM(char type[100])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    unsigned char k1[16];       // CFB
    RAND_bytes(k1, sizeof(k1)); //create random K1

    unsigned char k2[16];       //OFB
    RAND_bytes(k2, sizeof(k2)); //create random K2

    RAND_bytes(iv, sizeof(iv)); //create random iv

    int outlen;

    // encrypt K1 or K2, depending on the operating mode
    if (strcmp(type, "ECB") == 0 || strcmp(type, "ecb") == 0)
    {
        EVP_EncryptInit(ctx, EVP_aes_128_ecb(), k3, iv);
        EVP_EncryptUpdate(ctx, encriptedVect, &outlen, k1, sizeof(k1));
    }
    //criptarea cheilor k1 si k2
    if (strcmp(type, "CFB") == 0 || strcmp(type, "cfb") == 0)
    {
        EVP_EncryptInit(ctx, EVP_aes_128_ofb(), k3, iv);
        EVP_EncryptUpdate(ctx, encriptedVect, &outlen, k2, sizeof(k2));
    }

    //criptarea vectorului de initializare

    EVP_EncryptInit(ctx, EVP_aes_128_ofb(), k3, iv);
    EVP_EncryptUpdate(ctx, encriptInitVector, &outlen, iv, sizeof(iv));

    EVP_CIPHER_CTX_free(ctx); // elibereaza ctx
}

typedef struct thData
{
    int idThread; //id-ul thread-ului
    int B;        //socket descriptor client1
    int A;        //socket descriptor client2
} thData;

int i;

static void *treat(void *); /* functia executata de fiecare thread ce realizeaza comunicarea cu clientii */
void raspunde(void *);

int main()
{
    pthread_t th[100];

    cout << "inceput server " << endl;

    struct sockaddr_in client;
    struct sockaddr_in client2;
    struct sockaddr_in server;

    bzero(&server, sizeof(server));
    bzero(&client, sizeof(client));
    bzero(&client2, sizeof(client2));

    int sd; //descriptorul de socket
    if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
        perror("[server]Eroare la socket().\n");
        return errno;
    }

    int on = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    //server.sin_addr.s_addr = htonl (INADDR_ANY);
    server.sin_addr.s_addr = inet_addr(address);

    if (bind(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1) //crearea legaturii cu clientii
    {
        perror("[server]Eroare la bind().\n");
        return errno;
    }

    if (listen(sd, 5) == -1) //punem pe listen si asteptam clienti
    {
        perror("[server]Eroare la listen().\n");
        return errno;
    }

    while (1)
    {
        printf("[server]Asteptam la adresa %s si la portul %d...\n", address, PORT);
        fflush(stdout);
        int cllen = sizeof(client);
        int clsd = accept(sd, (struct sockaddr *)&client, (socklen_t *)&cllen);
        if (clsd < 0) // acceptarea clientului 1
        {
            perror("[server]Eroare la accept().\n");
            continue;
        }

        int cllen2 = sizeof(client2);
        int clsd2 = accept(sd, (struct sockaddr *)&client2, (socklen_t *)&cllen2);
        if (clsd2 < 0) // asteptarea clientului 2
        {
            perror("[server]Eroare la accept2().\n");
            continue;
        }

        thData *td; //parametru functia executata de thread

        td = (struct thData *)malloc(sizeof(struct thData));
        td->idThread = i++;
        td->B = clsd;
        td->A = clsd2;

        pthread_create(&th[i], NULL, &treat, td);
    }
}

static void *treat(void *arg)
{
    struct thData tdL;
    tdL = *((struct thData *)arg);

    printf("[thread]- %d - Asteptam mesajul...\n", tdL.idThread);
    fflush(stdout);

    pthread_detach(pthread_self());

    raspunde((struct thData *)arg);

    close((intptr_t)arg);
    return (NULL);
}
unsigned char encriptedMesajPrimitA[100]; //mesajul de confirmare primit de la A
unsigned char encriptedMesajPrimitB[100];

unsigned char decriptedMesajPrimitA[100]; //mesajul de confirmare decriptat primit de la A si B
unsigned char decriptedMesajPrimitB[100];

unsigned char criptedBlockPrimitA[100]; // blocul criptat primit de la A
unsigned char mesajTrimitereBlocA[100];
unsigned char encriptedBlock[16]; //encrypted block of chars -ec
unsigned char decriptedBlock[16]; //the decrypted block of char -c
char mesajConfirmareCitire[100];  //mesajul in care vedem daca mai avem caracatere de citit
char mesajInceputComunicare[16] = "start";
string line;

void raspunde(void *arg)
{

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    int outlen;

    struct thData tdL;
    tdL = *((struct thData *)arg);

    char mesajModA[100];
    char mesajModB[100];

    recv(tdL.A, &mesajModA, 100, 0); // received the operating mode from A
    recv(tdL.B, &mesajModB, 100, 0); // received the operating mode from B

    int randomMod = rand() % 2;
    //cout<<randomMod<<endl;

    if (strcmp(mesajModA, mesajModB) == 0) // daca cele doua moduri coincid
    {
        KM(mesajModA); // Crearea cheilor si a vectorului de initializare in modul ales

        send(tdL.A, &mesajModA, 100, 0); // am trimis modul de criptare lui A si B
        send(tdL.B, &mesajModA, 100, 0);

        send(tdL.A, &encriptedVect, 100, 0); //trimitem cheia criptata
        send(tdL.B, &encriptedVect, 100, 0);

        send(tdL.A, &iv, 100, 0); //trimitem vectorul de initializare criptat
        send(tdL.B, &iv, 100, 0);

        //recv(tdL.A, &mesajeTransmise, 100, 0); //receive the ready message from A
        //recv(tdL.B, &mesajeTransmise, 100, 0); //receive the ready message from B

        recv(tdL.A, &encriptedMesajPrimitA, 100, 0); // primeste mesajul de ready de la A si B criptat
        recv(tdL.B, &encriptedMesajPrimitB, 100, 0);
        cout << "am rpimit mesajul de incepere criptat" << endl;

        if (strcmp(mesajModA, "ECB") == 0 || strcmp(mesajModA, "ecb") == 0) // daca modul ales este ecb decripteaza cu k1
        {
            EVP_DecryptInit(ctx, EVP_aes_128_ecb(), k1, iv);
            EVP_DecryptUpdate(ctx, decriptedMesajPrimitA, &outlen, encriptedMesajPrimitA, sizeof(encriptedMesajPrimitA));
            EVP_DecryptInit(ctx, EVP_aes_128_ecb(), k1, iv);
            EVP_DecryptUpdate(ctx, decriptedMesajPrimitB, &outlen, encriptedMesajPrimitB, sizeof(encriptedMesajPrimitB));
            send(tdL.A, &mesajInceputComunicare, 100, 0);
            send(tdL.B, &mesajInceputComunicare, 100, 0);
            cout << "Am trimis inceputul de comunicare" << endl;
        }
        else //altfel, daca este cfb decripteaza cu k2
        {
            EVP_DecryptInit(ctx, EVP_aes_128_cfb(), k2, iv);
            EVP_DecryptUpdate(ctx, decriptedMesajPrimitA, &outlen, encriptedMesajPrimitA, sizeof(encriptedMesajPrimitA));
            EVP_DecryptInit(ctx, EVP_aes_128_cfb(), k2, iv);
            EVP_DecryptUpdate(ctx, decriptedMesajPrimitB, &outlen, encriptedMesajPrimitB, sizeof(encriptedMesajPrimitB));
            send(tdL.A, &mesajInceputComunicare, 100, 0);
            send(tdL.B, &mesajInceputComunicare, 100, 0);
            cout << "Am trimis inceputul de comunicare" << endl;
        }

        while (true)
        {
            cout << "Am intrat in while.Problema e mai jos." << endl;

            recv(tdL.A, &mesajConfirmareCitire, 128, 0);
            cout << "Am trimis la B " << endl; //confirmarea ca mai sunt sau nu caractere in fisier
            send(tdL.B, &mesajConfirmareCitire, 100, 0);

            if (strcmp(mesajConfirmareCitire, "finish") == 0)
                break;

            recv(tdL.A, &criptedBlockPrimitA, 100, 0); //primeste blocurile criptate de catre A

            //recv(tdL.A, &mesajTrimitereBlocA, 100, 0);

            cout << "Am primit de la A:" << criptedBlockPrimitA;

            send(tdL.B, &criptedBlockPrimitA, 100, 0);
        }

        recv(tdL.A, &mesajTrimitereBlocA, 100, 0);

        cout << "Am primit de la A:" << criptedBlockPrimitA;

        send(tdL.B, &criptedBlockPrimitA, 100, 0);
    }
    else if (randomMod == 1) //daca random este 1 va fi modul ecb, altfel va fi cfb
    {
        KM(mesajModA); // Crearea cheilor si a vectorului de initializare in modul ales

        send(tdL.A, &mesajModA, 100, 0); // am trimis modul de criptare lui A si B
        send(tdL.B, &mesajModA, 100, 0);

        send(tdL.A, &encriptedVect, 100, 0); //trimitem cheia criptata
        send(tdL.B, &encriptedVect, 100, 0);

        send(tdL.A, &iv, 100, 0); //trimitem vectorul de initializare criptat
        send(tdL.B, &iv, 100, 0);

        //recv(tdL.A, &mesajeTransmise, 100, 0); //receive the ready message from A
        //recv(tdL.B, &mesajeTransmise, 100, 0); //receive the ready message from B

        recv(tdL.A, &encriptedMesajPrimitA, 100, 0); // primeste mesajul de ready de la A si B criptat
        recv(tdL.B, &encriptedMesajPrimitB, 100, 0);
        cout << "am rpimit mesajul de incepere criptat" << endl;

        if (strcmp(mesajModA, "ECB") == 0 || strcmp(mesajModA, "ecb") == 0) // daca modul ales este ecb decripteaza cu k1
            EVP_DecryptInit(ctx, EVP_aes_128_ecb(), k1, iv);
            EVP_DecryptUpdate(ctx, decriptedMesajPrimitA, &outlen, encriptedMesajPrimitA, sizeof(encriptedMesajPrimitA));

            EVP_DecryptInit(ctx, EVP_aes_128_ecb(), k1, iv);
            EVP_DecryptUpdate(ctx, decriptedMesajPrimitB, &outlen, encriptedMesajPrimitB, sizeof(encriptedMesajPrimitB));

            send(tdL.A, &mesajInceputComunicare, 100, 0);
            send(tdL.B, &mesajInceputComunicare, 100, 0);
            cout << "Am trimis inceputul de comunicare" << endl;
        

        while (true)
        {
            cout << "Am intrat in while.Problema e mai jos." << endl;

            recv(tdL.A, &mesajConfirmareCitire, 128, 0);
            cout << "Am trimis la B " << endl; //confirmarea ca mai sunt sau nu caractere in fisier
            send(tdL.B, &mesajConfirmareCitire, 100, 0);

            if (strcmp(mesajConfirmareCitire, "finish") == 0)
                break;

            recv(tdL.A, &criptedBlockPrimitA, 100, 0); //primeste blocurile criptate de catre A

            //recv(tdL.A, &mesajTrimitereBlocA, 100, 0);

            cout << "Am primit de la A:" << criptedBlockPrimitA;

            send(tdL.B, &criptedBlockPrimitA, 100, 0);
        }

        recv(tdL.A, &mesajTrimitereBlocA, 100, 0);

        cout << "Am primit de la A:" << criptedBlockPrimitA;

        send(tdL.B, &criptedBlockPrimitA, 100, 0);
    }
    else  //modul cfb
    {
        KM(mesajModA); // Crearea cheilor si a vectorului de initializare in modul ales

        send(tdL.A, &mesajModA, 100, 0); // am trimis modul de criptare lui A si B
        send(tdL.B, &mesajModA, 100, 0);

        send(tdL.A, &encriptedVect, 100, 0); //trimitem cheia criptata
        send(tdL.B, &encriptedVect, 100, 0);

        send(tdL.A, &iv, 100, 0); //trimitem vectorul de initializare criptat
        send(tdL.B, &iv, 100, 0);

        //recv(tdL.A, &mesajeTransmise, 100, 0); //receive the ready message from A
        //recv(tdL.B, &mesajeTransmise, 100, 0); //receive the ready message from B

        recv(tdL.A, &encriptedMesajPrimitA, 100, 0); // primeste mesajul de ready de la A si B criptat
        recv(tdL.B, &encriptedMesajPrimitB, 100, 0);
        cout << "am primit mesajul de incepere criptat" << endl;

        /*if (strcmp(mesajModA, "ECB") == 0 || strcmp(mesajModA, "ecb") == 0) // daca modul ales este ecb decripteaza cu k1
        {
            EVP_DecryptInit(ctx, EVP_aes_128_ecb(), k1, iv);
            EVP_DecryptUpdate(ctx, decriptedMesajPrimitA, &outlen, encriptedMesajPrimitA, sizeof(encriptedMesajPrimitA));
            EVP_DecryptInit(ctx, EVP_aes_128_ecb(), k1, iv);
            EVP_DecryptUpdate(ctx, decriptedMesajPrimitB, &outlen, encriptedMesajPrimitB, sizeof(encriptedMesajPrimitB));
            send(tdL.A, &mesajInceputComunicare, 100, 0);
            send(tdL.B, &mesajInceputComunicare, 100, 0);
            cout << "Am trimis inceputul de comunicare" << endl;
        }
        else //altfel, daca este cfb decripteaza cu k2
        {*/
            EVP_DecryptInit(ctx, EVP_aes_128_cfb(), k2, iv);
            EVP_DecryptUpdate(ctx, decriptedMesajPrimitA, &outlen, encriptedMesajPrimitA, sizeof(encriptedMesajPrimitA));
            EVP_DecryptInit(ctx, EVP_aes_128_cfb(), k2, iv);
            EVP_DecryptUpdate(ctx, decriptedMesajPrimitB, &outlen, encriptedMesajPrimitB, sizeof(encriptedMesajPrimitB));
            send(tdL.A, &mesajInceputComunicare, 100, 0);
            send(tdL.B, &mesajInceputComunicare, 100, 0);
            cout << "Am trimis inceputul de comunicare" << endl;
        //}

        while (true)
        {
            cout << "Am intrat in while.Problema e mai jos." << endl;

            recv(tdL.A, &mesajConfirmareCitire, 128, 0);
            cout << "Am trimis la B " << endl; //confirmarea ca mai sunt sau nu caractere in fisier
            send(tdL.B, &mesajConfirmareCitire, 100, 0);

            if (strcmp(mesajConfirmareCitire, "finish") == 0)
                break;

            recv(tdL.A, &criptedBlockPrimitA, 100, 0); //primeste blocurile criptate de catre A

            //recv(tdL.A, &mesajTrimitereBlocA, 100, 0);

            cout << "Am primit de la A:" << criptedBlockPrimitA;

            send(tdL.B, &criptedBlockPrimitA, 100, 0);
        }

        recv(tdL.A, &mesajTrimitereBlocA, 100, 0);

        cout << "Am primit de la A:" << criptedBlockPrimitA;

        send(tdL.B, &criptedBlockPrimitA, 100, 0);
    }
}
