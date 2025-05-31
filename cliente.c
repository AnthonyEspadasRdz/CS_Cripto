#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define PORT 9999
#define buff_size 2048

void main(int argc, char *argv[])
{
  struct sockaddr_in socket_cliente;
  struct hostent *h;
  int fd;
  int n;
  char *host;
  char buf_ser[buff_size];
  char buf_cli[buff_size];

  // Genera el File Descriptor que usará el cliente durante la conexión
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  // Inicializa los atributos para establecer conexión con el servidor (struct sockaddr_in)
  memset((char *) &socket_cliente, 0, sizeof(socket_cliente));
  socket_cliente.sin_family = AF_INET;
  socket_cliente.sin_port = htons((u_short) PORT);
  h = gethostbyname( argv[1] );
  memcpy(&socket_cliente.sin_addr, h->h_addr, h->h_length);

  // Envía la solicitud de conexiń
  connect(fd, (struct sockaddr *) &socket_cliente, sizeof(socket_cliente));

  // Espera a recibir respuesta del servidor
  while (1)
  {
    // Lee la respuesta del usuario, se elimina el salto de linea
    n = read(0, buf_cli, sizeof(buf_cli));
    buf_cli[n-1] = (char*)0;
    buf_cli[n] = 0;

    // Envía mensaje al servidor
    send(fd, buf_cli, sizeof(buf_cli), 0);
    
    // Espera respuesta del servidor
    n = recv(fd, buf_ser, sizeof(buf_ser), 0);
    buf_ser[n] = '\n';
    ++n;
    buf_ser[n] = (char*)0;
    
    // Verifica que no se haya indicado la salida desde el servidor
    if (!strcmp(buf_ser, "exit")){  
      printf("\n");
      break;
    }

    // De no ser el caso, muestra la respuesta del servidor
    write(1, buf_ser, n);
    
    // Reinicimos el valor en los buffers
    memset(&(buf_ser), '\0', buff_size);
    memset(&(buf_cli), '\0', buff_size);
  }

    // Finaliza la conexión, tras el envío del mensaje, cerrando el File Descriptor
    close(fd);
    exit(0);
}