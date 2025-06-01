#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define PORT 9999
#define buff_size 2048
#define NONCE_LEN 16
#define FIRMA_MAX_LEN 256
#define ID_LEN 3
#define RUTA_TAM 64

void imprimirFirma(const unsigned char* buf, size_t len);

int main(int argc, char *argv[])
{
    // Variables para la conexión del socket
    struct sockaddr_in socket_cliente;
    struct hostent *h;
    int fd, n;
    char buf_ser[buff_size];
    char buf_cli[buff_size];

    // Variables para la firma digital
    unsigned char nonce[NONCE_LEN];
    unsigned char firma[FIRMA_MAX_LEN];
    size_t firma_len = FIRMA_MAX_LEN;
    char id[ID_LEN];
    strncpy(id, argv[1], ID_LEN);
    id[ID_LEN - 1] = '\0';
    printf("ID dispositivo: %s\n", id);

    // Cargar la llave privada del dispositivo
    char ruta_privada[RUTA_TAM];
    snprintf(ruta_privada, RUTA_TAM, "llaves/privada_%s.pem", id);
    FILE* fp = fopen(ruta_privada, "r");
    EVP_PKEY* llave_privada = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    // Generar nonce (valor fijo para coincidir con servidor)
    memset(nonce, 0xA5, sizeof(nonce));

    // Firmar el nonce
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, llave_privada);
    EVP_DigestSignUpdate(ctx, nonce, NONCE_LEN);
    EVP_DigestSignFinal(ctx, NULL, &firma_len);
    EVP_DigestSignFinal(ctx, firma, &firma_len);
    EVP_MD_CTX_free(ctx);

    printf("Firma generada (%zu bytes):\n", firma_len);
    imprimirFirma(firma, firma_len);

    // Guardar la firma en archivo local
    char ruta_firma[RUTA_TAM];
    snprintf(ruta_firma, RUTA_TAM, "firmas/firma_%s.txt", id);
    FILE* f = fopen(ruta_firma, "wb");
    fwrite(firma, 1, firma_len, f);
    fclose(f);
    printf("Firma guardada en %s\n", ruta_firma);

    // Crear socket y conectarse al servidor
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&socket_cliente, 0, sizeof(socket_cliente));
    socket_cliente.sin_family = AF_INET;
    socket_cliente.sin_port = htons((u_short) PORT);
    h = gethostbyname(argv[2]);
    memcpy(&socket_cliente.sin_addr, h->h_addr, h->h_length);
    connect(fd, (struct sockaddr *) &socket_cliente, sizeof(socket_cliente));

    // Enviar ID del dispositivo al servidor
    send(fd, id, sizeof(id), 0);

    // Ciclo de comunicación con el servidor
    while (1) {
        // Leer mensaje del usuario
        n = read(0, buf_cli, sizeof(buf_cli));
        buf_cli[n - 1] = '\0';

        // Enviar mensaje al servidor
        send(fd, buf_cli, sizeof(buf_cli), 0);

        // Esperar respuesta del servidor
        n = recv(fd, buf_ser, sizeof(buf_ser), 0);
        buf_ser[n] = '\n';
        ++n;
        buf_ser[n] = '\0';

        // Verificar si el servidor indicó salida
        if (!strcmp(buf_ser, "exit")) break;

        // Mostrar respuesta del servidor
        write(1, buf_ser, n);

        // Limpiar buffers
        memset(buf_ser, '\0', buff_size);
        memset(buf_cli, '\0', buff_size);
    }

    // Cerrar conexión
    close(fd);
    return 0;
}

// Función auxiliar para imprimir la firma en hexadecimal
void imprimirFirma(const unsigned char* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else printf(" ");
    }
    printf("\n");
}
