#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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

int identificarSalida(char *mensaje);                               // Funcion que determina cuando se debe salir del programa 

int main()
{
    // Variables requeridas para levantar el servidor  
    struct sockaddr_in servidor;
    struct sockaddr_in cliente;
    struct hostent* info_cliente;
    int fd_s, fd_c, n, num_cli = 1;
    int longClient;
    char buf[buff_size];

    // Variables de flujo para comunicacion
    int sigue = 1;                                                  // Variable para controlar el loop while
    
    // Generamos el File Descriptor para el servidor
    fd_s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	      
    // Se inicializan los valores del servidor (struct sockaddr_in)
    memset((char *) &servidor, 0, sizeof(servidor));
    servidor.sin_family = AF_INET;
    servidor.sin_addr.s_addr = INADDR_ANY;
    servidor.sin_port = htons((u_short) PORT);
    memset(&(servidor.sin_zero), '\0', 8);

    // Asocia el descriptor de archivo del servidor con su estructura correspondiente
    bind(fd_s, (struct sockaddr *) &servidor, sizeof(servidor));

    // Espera solicitud de conexión
    printf("Esperando conexión...\n");
    listen(fd_s, CLIENTES);

    longClient = sizeof(cliente);

while(1){

    // Establece conexión y genera File Descriptor para el cliente
    fd_c = accept(fd_s, (struct sockaddr *) &cliente, &longClient);

    // Obtiene la información del cliente y muestra desde donde se realiza la conexión
    info_cliente = gethostbyaddr((char *) &cliente.sin_addr, sizeof(struct in_addr), AF_INET);
    printf("Dispositivo %i conectado desde: %s\n\n", num_cli, info_cliente -> h_name);

    if (fork() == 0 )
    {

// ------------------------------------ Recepción de mensajes
        while (sigue != 0)
        {
            
            do{
            // Utiliza la variable n para detectar si ha recibido peticiones
            memset(&(buf), '\0', buff_size);
            n = recv(fd_c, buf, sizeof(buf), 0);
            
            // Colocamos NULL al final del buffer
            buf[n] = (char*)0;
            
            // Se omiten las respuestas que no tinen argumentos
            } while (*buf < 1);

            // Se valida que el primer comando sea distinto de 'exit'
            sigue = identificarSalida(buf);
            
            // Cuandos se identifica un 'exit' se termina la ejecucion y notifica al cliente
            if (!sigue){  
                send(fd_c, "exit", 5, 0);
                break;}                                             
            
            // Da respuesta al cliente
            send(fd_c, "Recibido", 8, 0);
        }

    // Finalizamos la conexión cerrando el File Descriptor del cliente
    close(fd_c);
    printf("\nConexion con Dispositivo %i finalizada\n", num_cli);
    exit(0);
    }
    
    // El proceso padre cierra el descriptor del cliente y sigue aceptando peticiones
    else 
    {
        close(fd_c);
        ++num_cli;
    }

// ----------------------------------------------------------------------------------------
} // cierra while(1)

    // Dejamos de responder solicitudes cerrando el File Descriptor del servidor
    close(fd_s);
    shutdown( fd_s, SHUT_RDWR );
    exit(0);
}

int identificarSalida(char *mensaje)
{
    int contador = 0;                                           // Contador para recorrer el arreglo
    int receptor = 0;                                           // Contador para el numero efectivo de caracteres leídos
    char exit[4];                                               // Arreglo que recibe los caracteres efectivos leídos

    while(contador < 256)                                        // El limite del contador es el tamaño del arreglo
    {
        if (isblank(mensaje[contador]))                         // Si no hay un caracter, el contador avanza
        {
            contador++;
        } else
        {
            exit[receptor] = mensaje[contador];                 // Si es un caracter, se guarda y aumentan los contadores
            contador++;                                         
            receptor++;
        }

        if (receptor == 4)                                      // Cuando el receptor llega a 4 se han leido 4 caracteres
        {
            return strcmp(exit, "exit");                        // Si se ingreso el comando exit, la salida será 0;
        }
    }
}