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
  struct sockaddr_in socket_cliente;
  struct hostent *h;
  int fd, n;
  char buf_ser[buff_size];
  char buf_cli[buff_size];

  unsigned char nonce[NONCE_LEN];
  unsigned char firma[FIRMA_MAX_LEN];
  size_t firma_len = FIRMA_MAX_LEN;
  char id[ID_LEN];
  strncpy(id, argv[1], ID_LEN);
  id[ID_LEN - 1] = '\0';
  printf("ID dispositivo: %s\n", id);

  // generar rutas
  char ruta_privada[RUTA_TAM];
  snprintf(ruta_privada, RUTA_TAM, "llaves/privada_%s.pem", id);

  FILE* fp = fopen(ruta_privada, "r");
  EVP_PKEY* llave_privada = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);

  // firma
  RAND_bytes(nonce, NONCE_LEN);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, llave_privada);
  EVP_DigestSignUpdate(ctx, nonce, NONCE_LEN);
  EVP_DigestSignFinal(ctx, NULL, &firma_len);
  EVP_DigestSignFinal(ctx, firma, &firma_len);
  EVP_MD_CTX_free(ctx);

  printf("Firma generada (%zu bytes):\n", firma_len);
  imprimirFirma(firma, firma_len);

  // guardar firma en archivo
  char ruta_firma[RUTA_TAM];
  snprintf(ruta_firma, RUTA_TAM, "firmas/firma_%s.txt", id);
  FILE* f = fopen(ruta_firma, "wb");
  fwrite(firma, 1, firma_len, f);
  fclose(f);
  printf("Firma guardada en %s\n", ruta_firma);

  // conexión al servidor
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  memset((char *) &socket_cliente, 0, sizeof(socket_cliente));
  socket_cliente.sin_family = AF_INET;
  socket_cliente.sin_port = htons((u_short) PORT);
  h = gethostbyname(argv[2]);
  memcpy(&socket_cliente.sin_addr, h->h_addr, h->h_length);
  connect(fd, (struct sockaddr *) &socket_cliente, sizeof(socket_cliente));

  // enviar ID
  send(fd, id, sizeof(id), 0);

  // ciclo de comunicación
  while (1) {
    n = read(0, buf_cli, sizeof(buf_cli));
    buf_cli[n - 1] = '\0';
    send(fd, buf_cli, sizeof(buf_cli), 0);

    n = recv(fd, buf_ser, sizeof(buf_ser), 0);
    buf_ser[n] = '\n';
    ++n;
    buf_ser[n] = '\0';

    if (!strcmp(buf_ser, "exit")) break;

    write(1, buf_ser, n);
    memset(buf_ser, '\0', buff_size);
    memset(buf_cli, '\0', buff_size);
  }

  close(fd);
  return 0;
}

void imprimirFirma(const unsigned char* buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02X", buf[i]);
    if ((i + 1) % 16 == 0) printf("\n");
    else printf(" ");
  }
  printf("\n");
}
