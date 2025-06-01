#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define CLIENTES 10
#define PORT 9999
#define buff_size 2048
#define RUTA_TAM 64

int identificarSalida(char *mensaje);
void imprimirFirma(const unsigned char* buf, size_t len);

// Función principal que levanta el servidor y gestiona conexiones entrantes
int main()
{
    struct sockaddr_in servidor, cliente;
    struct hostent* info_cliente;
    int fd_s, fd_c, n;
    int longClient;
    char buf[buff_size];
    int sigue = 1;

    // Crear socket del servidor
    fd_s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&servidor, 0, sizeof(servidor));
    servidor.sin_family = AF_INET;
    servidor.sin_addr.s_addr = INADDR_ANY;
    servidor.sin_port = htons(PORT);
    memset(&(servidor.sin_zero), '\0', 8);

    bind(fd_s, (struct sockaddr *) &servidor, sizeof(servidor));
    printf("Esperando conexión...\n");
    listen(fd_s, CLIENTES);
    longClient = sizeof(cliente);

    while (1) {
        fd_c = accept(fd_s, (struct sockaddr *) &cliente, &longClient);
        info_cliente = gethostbyaddr((char *) &cliente.sin_addr, sizeof(struct in_addr), AF_INET);

        if (fork() == 0) {
            char id_dispo[3];

            // El primer mensaje contiene el ID del dispositivo (3 bytes)
            memset(buf, '\0', buff_size);
            n = recv(fd_c, buf, 3, MSG_WAITALL);
            buf[3] = '\0';
            strncpy(id_dispo, buf, 3);
            printf("\nDispositivo %s conectado desde: %s\n", id_dispo, info_cliente->h_name);

            // Ruta del archivo donde se guardó previamente la firma
            char ruta_firma[RUTA_TAM];
            snprintf(ruta_firma, RUTA_TAM, "firmas/firma_%s.txt", id_dispo);
            FILE* f = fopen(ruta_firma, "rb");
            if (!f) {
                perror("Error al abrir firma");
                close(fd_c);
                exit(1);
            }

            // Se lee la firma desde el archivo correspondiente
            unsigned char firma_dispo[256];
            size_t firma_len = fread(firma_dispo, 1, sizeof(firma_dispo), f);
            fclose(f);
            printf("Firma recibida desde archivo (%zu bytes):\n", firma_len);
            imprimirFirma(firma_dispo, firma_len);

            // Ruta del archivo de llave pública correspondiente al dispositivo
            char ruta_publica[RUTA_TAM];
            snprintf(ruta_publica, RUTA_TAM, "llaves/publica_%s.pem", id_dispo);
            FILE* pubf = fopen(ruta_publica, "r");
            if (!pubf) {
                perror("Error al abrir llave pública");
                close(fd_c);
                exit(1);
            }

            EVP_PKEY* pubkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);
            fclose(pubf);
            if (!pubkey) {
                fprintf(stderr, "No se pudo leer la llave pública\n");
                close(fd_c);
                exit(1);
            }

            // Genera un nonce fijo (debe coincidir con el usado por el cliente)
            unsigned char nonce[16];
            memset(nonce, 0xA5, sizeof(nonce));

            // Verifica la firma con la llave pública, el hash SHA-256 y el nonce
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey);
            EVP_DigestVerifyUpdate(ctx, nonce, sizeof(nonce));
            int verificacion = EVP_DigestVerifyFinal(ctx, firma_dispo, firma_len);
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pubkey);

            if (verificacion == 1) {
                printf("La firma corresponde con el dispositivo %s\n", id_dispo);
            } else if (verificacion == 0) {
                printf("La firma no corresponde %s\n", id_dispo);
            } else {
                printf("Error al verificar la firma\n");
            }

            // Ciclo de mensajes
            while (sigue != 0) {
                do {
                    memset(buf, '\0', buff_size);
                    n = recv(fd_c, buf, sizeof(buf), 0);
                    buf[n] = '\0';
                } while (*buf < 1);

                sigue = identificarSalida(buf);
                if (!sigue) {
                    send(fd_c, "exit", 5, 0);
                    break;
                }

                send(fd_c, "Recibido", 8, 0);
            }

            close(fd_c);
            printf("Conexión con Dispositivo %s finalizada\n", id_dispo);
            exit(0);
        } else {
            close(fd_c);
        }
    }

    close(fd_s);
    shutdown(fd_s, SHUT_RDWR);
    return 0;
}

// Detecta si el mensaje recibido es "exit"
int identificarSalida(char *mensaje)
{
    int contador = 0, receptor = 0;
    char exit[4];

    while (contador < 256) {
        if (isblank(mensaje[contador])) {
            contador++;
        } else {
            exit[receptor++] = mensaje[contador++];
        }

        if (receptor == 4) {
            return strcmp(exit, "exit");
        }
    }
}

// Imprime la firma en hexadecimal
void imprimirFirma(const unsigned char* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else printf(" ");
    }
    printf("\n");
}