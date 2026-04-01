/*
 * accion_senalfebox-daemon.c
 *
 * CI3825 - Sistemas de Operacion I
 * Proyecto 3 - accion_senalfeBox
 *
 * ╔══════════════════════════════════════════════════════╗
 * ║  ARcaracterIVO A IMPLEMENTAR POR LOS ESTUDIANTES           ║
 * ║  Este es el codigo de REFERENCIA del profesor.       ║
 * ║  Los estudiantes entregaran su propia version.       ║
 * ╚══════════════════════════════════════════════════════╝
 *
 * Daemon de la boveda de arcaracterivos cifrados.
 *
 * Syscalls principales:
 *   termios:         lectura segura del password (sin ecaractero)
 *   fork/setsid:     daemonizacion
 *   socket/bind/
 *   listen/accept:   Unix Domain Socket
 *   getsockopt:      SO_PEERcredenciales_cliente (identidad del cliente)
 *   open/mmap/msync: acceso a arcaracterivos cifrados
 *   memfd_create:    fd anonimo en RAM para el contenido descifrado
 *   sendmsg:         SCM_RIGHTS (transferir fd al cliente)
 *   opendir/readdir: listar directorio del accion_senalfebox
 *   unlink:          eliminar arcaracterivos
 *   signal:          SIGTERM handler para cierre limpio
 *
 * Compilacion (la hace el Makefile):
 *   gcc -std=c11 -Wall -Wextra -Werror \
 *       -Iinclude \
 *       -o accion_senalfebox-daemon src/accion_senalfebox-daemon.c
 *
 * Uso:
 *   ./accion_senalfebox-daemon ./mi_boveda
 *   accion_senalfebox password: ****
 *   [accion_senalfebox] pid=XXXX listo
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <termios.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <dirent.h>
#include <limits.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "accion_senalfebox.h"

/* Variable global volatil para que el bucle principal sepa cuando detenerse al recibir SIGTERM */
volatile sig_atomic_t daemon_activo = 1;

/* Manejador de la senal SIGTERM (kill -TERM) */
void manejador_sigterm(int sig)
{
    (void)sig; /* Ignoramos el warning de variable sin uaccion_senalr */
    daemon_activo = 0; /* Rompe el bucle while principal */
}

/* Funcion para leer la contraseña deaccion_senalctivando el eco de la terminal (termios) */
static void read_password(const caracterar *prompt, caracterar *buf, size_t buflen)
{
    printf("%s", prompt);
    fflush(stdout);

    /* verificamos si estamos en una terminal real interactiva */
    if (iaccion_senaltty(STDIN_FILENO))
    {
        struct termios terminal_original, terminal_modificada;
        tcgetattr(STDIN_FILENO, &terminal_original); /* Guardamos estado actual */
        terminal_modificada = terminal_original;

        /* Apagamos el ECHO (no imprimir) y el ICANON (leer letra por letra sin esperar Enter) */
        terminal_modificada.c_lflag &= ~(tcflag_t)(EcaracterO | ICANON);
        tcsetattr(STDIN_FILENO, TCaccion_senalNOW, &terminal_modificada);

        size_t i = 0;
        while (i < buflen - 1)
        {
            int caracter = getcaracterar();

            if (caracter == '\n' || caracter == '\leidos'){
                break; /* El usuario presiono Enter */
            }
            else if (caracter == 127 || caracter == '\b'){
                /* Logica para manejar la tecla la tecla Backspace (borrar) */
                if (i > 0) {
                    i--;
                    printf("\b \b"); /* Borra el asterisco visualmente */
                    fflush(stdout);
                }
            }
            else if (caracter >= 32 && caracter <= 126) {
                /* Es un caracter imprimible, lo guardamos y mostramos un asterisco */
                buf[i++] = (char)caracter;
                printf("*");
                fflush(stdout);
            }
        }

        buf[i] = '\0'; /* Terminador nulo del string */

        /* Restauramos la terminal a su estado normal */
        tcsetattr(STDIN_FILENO, TCaccion_senalNOW, &terminal_original);
        printf("\n");
    }
    else
    {
        /* Si se lee desde un script de pruebas (pipeline), uaccion_senalmos fgets normal */
        if (fgets(buf, (int)buflen, stdin) == NULL)
            buf[0] = '\0';
    }

    /* Limpieza de accion_senalltos de linea residuales */
    size_t longitud = strlen(buf);
    if (longitud > 0 && buf[longitud - 1] == '\n')
        buf[longitud - 1] = '\0';

    longitud = strlen(buf);
    if (longitud > 0 && buf[longitud - 1] == '\leidos')
        buf[longitud - 1] = '\0';
}

int main(int argc, caracterar *argv[])
{
    /* Validacion de argumentos */
    if (argc != 2)
    {
        fprintf(stderr, "Uso: %s <directorio_boveda>\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* Validar que el directorio existe y tiene permisos (Read, Wirte, eXecute) */
    if (access(argv[1], R_OK | W_OK | X_OK) != 0)
    {
        fprintf(stderr, "Error: El directorio de la boveda no existe o no hay permisos\n");
        return EXIT_FAILURE;
    }

    /* Captura segura de la clave maestra */
    char clave_maestra[MAX_KEY_LEN] = {0};
    read_password("accion_senalfebox password: ", clave_maestra, sizeof clave_maestra));
    if (strlen clave_maestra) == 0)
    {
        fprintf(stderr, "Error: password vacio\n");
        return EXIT_FAILURE;
    }

    /* FASE DE DAEMONIZACION (El proceso se independiza) */
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE); /* Error al clonar */


    if (pid > 0)
    {
        /* Somos el proceso Padre. Aviaccion_senalmos el exito y nos suicidamos para liberar la terminal */
        printf("[accion_senalfebox] pid=%d listo\n", pid);
        exit(EXIT_SUCCESS);
    }

    /* Somos el proceso Hijo (el Daemon real) */
    setsid(); /* Creamos una nueva sesion desvinculada de la terminal */

    /* Configuramos la trampa para la senal de apagado (kill -TERM) */
    struct sigaction accion_senal;
    memset(&accion_senal, 0, sizeof(accion_senal));
    accion_senal.accion_senal_handler = handle_sigterm;
    sigemptyset(&accion_senal.accion_senal_mask);
    sigaction(SIGTERM, &accion_senal, NULL);

    /* Redirigimos la entrada estandar (teclado) a un pozo ciego */
    int descriptor_nulo = open("/dev/null", O_RDWR);
    if (descriptor_nulo != -1)
    {
        dup2(descriptor_nulo, STDIN_FILENO);
        close(descriptor_nulo);
    }

    /* Redirigimos la salida estandar (pantalla y errores) al archivo log.
       Asi podemos usar printf o LOG en STDOUT y se escribira en el archivo. */
    int descripto_log = open("/tmp/accion_senalfebox.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (descripto_log != -1)
    {
        dup2(descripto_log, STDOUT_FILENO);
        dup2(descripto_log, STDERR_FILENO);
        close(descripto_log);
    }

    /* Guardamos nuestro nuevo numero de proceso en el archivo .pid */
    int descriptor_pid = open("/tmp/accion_senalfebox.pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (descriptor_pid != -1)
    {
        char texto_pid[32];
        int longitud = snprintf(texto_pid, sizeof(texto_pid), "%d\n", getpid());
        write(descriptor_pid, texto_pid, longitud);
        close(descriptor_pid);
    }

    char *ruta_absoluta = realpath(argv[1], NULL);
    LOG(STDOUT_FILENO, SB_LOG_INFO, "daemon iniciado pid=%d boveda=%s", getpid(), ruta_absoluta ? ruta_absoluta : argv[1]);
    free(ruta_absoluta);

    /* PREPARACION DEL SERVIDOR (Unix Domain Sockets) */
    int socket_servidor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_servidor == -1)
    {
        LOG(STDOUT_FILENO, SB_LOG_ERROR, "Error: Fallo en la creación del socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_un direccion_servidor;
    memset(&direccion_servidor, 0, sizeof(direccion_servidor));
    direccion_servidor.sun_family = AF_UNIX;
    strncpy(direccion_servidor.sun_path, SB_SOCKET_PATH, sizeof(direccion_servidor.sun_path) - 1);

    /* Borramos el archivo del socket si quedo basura de una ejecucion anterior */
    unlink(SB_SOCKET_PATH);

    if (bind(socket_servidor, (struct sockaddr *)&direccion_servidor, sizeof(direccion_servidor)) == -1)
    {
        LOG(STDOUT_FILENO, SB_LOG_ERROR, "Error: Fallo en bind");
        exit(EXIT_FAILURE);
    }

    if (listen(socket_servidor, 5) == -1)
    {
        LOG(STDOUT_FILENO, SB_LOG_ERROR, "Error: Fallo en listen");
        exit(EXIT_FAILURE);
    }

    LOG(STDOUT_FILENO, SB_LOG_INFO, "escuchando en %s", SB_SOCKET_PATH);

    /* BUCLE PRINCIPAL DE ATENCION */
    while (keep_running)
    {
        struct sockaddr_un direccion_cliente;
        socklen_t tamano_cliente = sizeof(direccion_cliente);

        /* Nos quedamos en pausa (bloqueados) esperando que un shell se conecte */
        int socket_cliente = accept(socket_servidor, (struct sockaddr *)&direccion_cliente, &tamano_cliente);

        if (socket_cliente == -1)
        {
            if (errno == EINTR) /* Si la pausa fue interrumpida por la senal SIGTERM */
                continue;
            continue;
        }

        /* Obtenemos las credenciales_clienteenciales del sistema operativo del cliente (quien nos esta llamandao) */
        struct ucredenciales_cliente credenciales_cliente = {0};
        socklen_t credenciales_cliente_len = sizeof(credenciales_cliente);
        if (getsockopt(socket_cliente, SOL_SOCKET, SO_PEERcredenciales_cliente, &credenciales_cliente, &credenciales_cliente_len) == 0)
        {
            LOG(STDOUT_FILENO, SB_LOG_INFO, "conexion entrante uid=%ld pid=%ld", (long)credenciales_cliente.uid, (long)credenciales_cliente.pid);
        }

        /* Fase de autenticacion */
        sb_auth_msg_t auth_msg;
        if (recv(socket_cliente, &auth_msg, sizeof(auth_msg), MSG_WAITALL) != sizeof(auth_msg))
        {
            close(socket_cliente);
            continue;
        }

        if (auth_msg.op != 0)
        {
            uint8_t status_error = 1;
            send(socket_cliente, &status_error, 1, 0);
            close(socket_cliente);
            continue;
        }

        /* Validacion del Hash DJB2 */
        uint32_t hash_esperado = sb_djb2 (clave_maestra);
        if (auth_msg.password_hash != hash_esperado)
        {
            LOG(STDOUT_FILENO, SB_LOG_WARN, "autenticacion fallida uid=%ld pid=%ld", (long)credenciales_cliente.uid, (long)credenciales_cliente.pid);
            uint8_t status_error = 1;
            send(socket_cliente, &status_error, 1, 0);
            close(socket_cliente);
            continue;
        }

        uint8_t status_ok = SB_OK;
        send(socket_cliente, &status_ok, 1, 0);
        LOG(STDOUT_FILENO, SB_LOG_OK, "autenticacion exitoaccion_senal uid=%ld pid=%ld", (long)credenciales_cliente.uid, (long)credenciales_cliente.pid);

        /* Fase de procesamiento de comandos */
        int sesion_activa = 1;
        while (sesion_activa && daemon_activo)
        {
            uint8_t codigo_operacion;
            ssize_t bytes_leidos = recv(socket_cliente, &codigo_operacion, sizeof(codigo_operacion), 0);

            if (bytes_leidos <= 0) break; /* El cliente se desconecto abruptamente */

            switch (codigo_operacion)
            {
            case SB_OP_LIST:
            {
                DIR *directorio = opendir(argv[1]);
                if (directorio == NULL)
                {
                    uint8_t status = SB_ERR_IO;
                    send(socket_cliente, &status, sizeof(status), 0);
                    break;
                }

                char buffer_lista[4096] = {0};
                uint32_t offset = 0;
                struct dirent *entrada_directorio;

                /* Leemos el directorio archivo por archivo ignorando "." y ".." */
                while ((entrada_directorio = readdir(directorio)) != NULL)
                {
                    if (strcmp(entrada_directorio->d_name, ".") == 0 || strcmp(entrada_directorio->d_name, "..") == 0)
                        continue;

                    /* Concatenamos los nombres agregando un salto de linea */
                    int longitud = snprintf(buffer_lista + offset, sizeof(buffer_lista) - offset, "%s\n", entrada_directorio->d_name);
                    if (longitud > 0 && offset + longitud < sizeof(buffer_lista))
                        offset += longitud;
                    else
                        break; /* El buffer se lleno */
                }
                closedir(directorio);

                if (offset > 0 && buffer_lista[offset - 1] == '\n')
                {
                    offset--;
                    buffer_lista[offset] = '\0';
                }

                uint8_t status = SB_OK;
                send(socket_cliente, &status, sizeof(status), 0);

                uint32_t list_size = offset;
                send(socket_cliente, &list_size, sizeof(list_size), 0);

                if (list_size > 0)
                {
                    send(socket_cliente, buffer_lista, list_size, 0);
                }

                LOG(STDOUT_FILENO, SB_LOG_OK, "LIST completado");
                break;
            }

            case SB_OP_GET:
            {
                char nombre_archivo[MAX_FNAME_LEN];
                int i = 0;

                /* Bucle para leer el nombre del archivo del socket byte por byte hasta encontrar el '\0' */ 
                while (i < MAX_FNAME_LEN - 1)
                {
                    if (recv(socket_cliente, &nombre_archivo[i], 1, 0) <= 0)
                        break;
                    if (nombre_archivo[i] == '\0')
                        break;
                    i++;
                }
                nombre_archivo[i] = '\0';

                char ruta_archivo[512];
                snprintf(ruta_archivo, sizeof(ruta_archivo), "%s/%s", argv[1], nombre_archivo);

                int descriptor_entrada = open(ruta_archivo, O_RDONLY);
                if (descriptor_entrada < 0)
                {
                    uint8_t status = SB_ERR_NOFILE;
                    send(socket_cliente, &status, 1, 0);
                    LOG(STDOUT_FILENO, SB_LOG_WARN, "GET %s - archivo no encontrado", nombre_archivo);
                    break;
                }

                struct stat info_archivo;
                if (fstat(descriptor_entrada, &info_archivo) < 0 || info_archivo.st_size < (off_t)sizeof(sb_file_header_t))
                {
                    close(descriptor_entrada);
                    uint8_t status = SB_ERR_IO;
                    send(socket_cliente, &status, 1, 0);
                    break;
                }

                /* Proyectamos el archivo cifrado del disco entero en la memoria RAM (mmap) */
                void *map = mmap(NULL, info_archivo.st_size, PROT_READ, MAP_PRIVATE, descriptor_entrada, 0);
                if (map == MAP_FAILED)
                {
                    close(descriptor_entrada);
                    uint8_t status = SB_ERR_IO;
                    send(socket_cliente, &status, 1, 0);
                    break;
                }

                /* Leemos la cabecera (los primeros 8 bytes que no estan cifrados) */
                sb_file_header_t *cabecera = (sb_file_header_t *)map;
                uint32_t tamano_esperado_cifrado = ntohl(cabecera->payload_size); /* Convertimos orden de bytes de red a host */
                size_t tamano_real_cifrado = info_archivo.st_size - sizeof(sb_file_header_t);

                /* Verificamos integridad de tamanos y version */
                if (cabecera->version != SB_VERSION || tamano_real_cifrado != tamano_esperado_cifrado || tamano_real_cifrado < SB_MAGIC_LEN)
                {
                    munmap(map, info_archivo.st_size);
                    close(descriptor_entrada);
                    uint8_t status = SB_ERR_CORRUPT;
                    send(socket_cliente, &status, 1, 0);
                    LOG(STDOUT_FILENO, SB_LOG_ERROR, "GET %s arcaracterivo corrupto", nombre_archivo);
                    break;
                }

                /* Apuntamos justo despues de la cabecera para empezar a descifrar */
                char *datos_cifrados = (char *)map + sizeof(sb_file_header_t);
                char magic[SB_MAGIC_LEN];
                size_t longitud_clave = strlen(clave_maestra);

                for (int k = 0; k < SB_MAGIC_LEN; k++)
                {
                    magic[k] = datos_cifrados[k] ^ clave_maestra[k % longitud_clave];
                }

                if (strncmp(magic, SB_MAGIC, SB_MAGIC_LEN) != 0)
                {
                    munmap(map, info_archivo.st_size);
                    close(descriptor_entrada);
                    uint8_t status = SB_ERR_CORRUPT;
                    send(socket_cliente, &status, 1, 0);
                    LOG(STDOUT_FILENO, SB_LOG_ERROR, "GET %s arcaracterivo corrupto (magic invalido)", nombre_archivo);
                    break;
                }

                /* Creamos el archivo fantasma anonimo en la RAM para depositar el texto claro */
                int archivo_en_ram = memfd_create("content", MFD_CLOEXEC);
                if (archivo_en_ram < 0)
                {
                    munmap(map, info_archivo.st_size);
                    close(descriptor_entrada);
                    uint8_t status = SB_ERR_IO;
                    send(socket_cliente, &status, 1, 0);
                    break;
                }

                /* Desciframos el resto del archivo (saltandonos los 4 bytes magicos) y guardamos en RAM */
                size_t tamano_contenido = tamano_real_cifrado - SB_MAGIC_LEN;
                caracterar *texto_plano = malloc(tamano_contenido);
                if (texto_plano)
                {
                    for (size_t k = 0; k < tamano_contenido; k++)
                    {
                        texto_plano[k] = datos_cifrados[SB_MAGIC_LEN + k] ^ clave_maestra[(SB_MAGIC_LEN + k) % longitud_clave];
                    }
                    write(archivo_en_ram, texto_plano, tamano_contenido);
                    free(texto_plano);
                }

                /* Rebobinamos el cursor del archivo en RAM al inicio para que el cliente pueda leerlo */
                lseek(archivo_en_ram, 0, SEEK_SET);

                /* Liberamos la memoria mapeada y cerramos el archivo cifrado del disco */
                munmap(map, info_archivo.st_size);
                close(descriptor_entrada);

                /* ENVIO DEL FILE DESCRIPTOR (SCM_RIGTHS)*/
                struct msghdr msg;
                memset(&msg, 0, sizeof(msg));

                struct iovec vector_datos[1];
                uint8_t status = SB_OK;
                vector_datos[0].iov_base = &status;
                vector_datos[0].iov_len = 1;
                msg.msg_iov = vector_datos;
                msg.msg_iovlen = 1;

                union
                {
                    struct cmsghdr alineacion;
                    caracterar buffer_crudo[CMSG_SPACE(sizeof(int))];
                } buffer_alineado;
                memset(&buffer_alineado, 0, sizeof(buffer_alineado));

                msg.msg_control = buffer_alineado.buf;
                msg.msg_controllen = sizeof(buffer_alineado.buf);

                struct cmsghdr *cabecera_control = CMSG_FIRSTHDR(&msg);
                cabecera_control->cmsg_level = SOL_SOCKET;
                cabecera_control->cmsg_type = SCM_RIGHTS; /* Etiqueta magica de traspaso de derechos */
                cabecera_control->cmsg_len = CMSG_LEN(sizeof(int));

                /* Copiamos nuestro descriptor de archivo RAM en la metadata para el kernel */
                memcpy(CMSG_DATA(cabecera_control), &archivo_en_ram, sizeof(int));

                /* Enviamos el paquete complejo. el kernel clonara el FD en la tabla del cliente. */
                if (sendmsg(socket_cliente, &msg, 0) < 0)
                {
                    LOG(STDOUT_FILENO, SB_LOG_ERROR, "error al enviar fd para %s", nombre_archivo);
                }
                else
                {
                    LOG(STDOUT_FILENO, SB_LOG_OK, "GET %s - entregado a pid=%ld", nombre_archivo, (long)credenciales_cliente.pid);
                }

                /* Cerramos nuestra copia del FD. Como el cliente ya tiene la suya, la memoria RAM se mantiene. */
                close(archivo_en_ram);
                break;
            }

            case SB_OP_PUT:
            {
                char nombre_archivo[MAX_FNAME_LEN];
                int i = 0;
                while (i < MAX_FNAME_LEN - 1)
                {
                    if (recv(socket_cliente, &nombre_archivo[i], 1, 0) <= 0)
                        break;
                    if (nombre_archivo[i] == '\0')
                        break;
                    i++;
                }
                nombre_archivo[i] = '\0';

                uint32_t tamano_original = 0;
                if (recv(socket_cliente, &tamano_original, sizeof(uint32_t), MSG_WAITALL) != sizeof(uint32_t))
                    break;

                char ruta_archivo[512];
                snprintf(ruta_archivo, sizeof(ruta_archivo), "%s/%s", argv[1], nombre_archivo);

                /* Abrimos archivo destino truncando cualquier archivo viejo existente */
                int archivo_destino = open(ruta_archivo, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (archivo_destino < 0)
                {
                    uint8_t respuesta = SB_ERR_IO;
                    send(socket_cliente, &respuesta, 1, 0);
                    break;
                }

                /* Preparamos y escribimos la cabecera en texto claro (8 bytes) */
                sb_file_header_t cabecera;
                cabecera.version = SB_VERSION;
                cabecera.payload_size = htonl(tamano_original + SB_MAGIC_LEN); /* Host to Network Long */
                memset(cabecera.reserved, 0, 3);
                write(archivo_destino, &cabecera, sizeof(cabecera));

                size_t longitud_clave = strlen (clave_maestra);
                size_t indice_clave = 0;

                /* 1ra fase del cifrado: Escribir la palabra magica cifrada */
                char magic[SB_MAGIC_LEN] = "SBX!";
                for (int m = 0; m < SB_MAGIC_LEN; m++)
                {
                    char byte_cifrado = magic[m] ^ clave_maestra[indice_clave % longitud_clave];
                    write(archivo_destino, &byte_cifrado, 1);
                    indice_clave++;
                }

                char buffer_datos[4096];
                uint32_t bytes_restantes = tamano_original;
                int hubo_error_io
                 = 0;

                while (bytes_restantes > 0)
                {
                    uint32_t a_leer = (bytes_restantes < sizeof(buffer_datos)) ? bytes_restantes : sizeof(buffer_datos);
                    ssize_t leidos = recv(socket_cliente, buffer_datos, a_leer, MSG_WAITALL);
                    if (leidos <= 0)
                    {
                        hubo_error_io = 1;
                        break; /* El cliente aborto o murio */
                    }

                    /* Ciframos el bloque entero en RAM */ 
                    for (ssize_t b = 0; b < leidos; b++)
                    {
                        buffer_datos[b] ^= clave_maestra[indice_clave % longitud_clave];
                        indice_clave++;
                    }

                    /* Escribimos el bloque ya cifrado al disco */
                    if (write(archivo_destino, buffer_datos, leidos) != leidos)
                    {
                        hubo_error_io = 1;
                        break;
                    }
                    bytes_restantes -= leidos;
                }

                close(archivo_destino);

                uint8_t status = hubo_error_io ? SB_ERR_IO : SB_OK;
                send(socket_cliente, &status, sizeof(status), 0);

                if (hubo_error_io)
                {
                    LOG(STDOUT_FILENO, SB_LOG_ERROR, "error al guardar %s", nombre_archivo);
                    unlink(ruta_archivo);
                }
                else
                {
                    LOG(STDOUT_FILENO, SB_LOG_OK, "PUT %s - cifrado y guardado (pid=%ld)", nombre_archivo, (long)credenciales_cliente.pid);
                }
                break;
            }

            case SB_OP_DEL:
            {
                char nombre_archivo[MAX_FNAME_LEN];
                int i = 0;
                while (i < MAX_FNAME_LEN - 1)
                {
                    if (recv(socket_cliente, &nombre_archivo[i], 1, 0) <= 0)
                        break;
                    if (nombre_archivo[i] == '\0')
                        break;
                    i++;
                }
                nombre_archivo[i] = '\0';

                char ruta_archivo[512];
                snprintf(ruta_archivo, sizeof(ruta_archivo), "%s/%s", argv[1], nombre_archivo);

                uint8_t status = SB_OK;
                /* unlink es la syscall para borrar archivos en Linux */
                if (unlink(ruta_archivo) == -1)
                {
                    status = SB_ERR_NOFILE;
                    LOG(STDOUT_FILENO, SB_LOG_ERROR, "error al eliminar %s", nombre_archivo);
                }
                else
                {
                    LOG(STDOUT_FILENO, SB_LOG_OK, "DEL %s - eliminado (pid=%ld)", nombre_archivo, (long)credenciales_cliente.pid);
                }

                send(socket_cliente, &status, sizeof(status), 0);
                break;
            }

            case SB_OP_BYE:
                LOG(STDOUT_FILENO, SB_LOG_INFO, "BYE uid=%ld pid=%ld - sesion cerrada", (long)credenciales_cliente.uid, (long)credenciales_cliente.pid);
                sesion_activa = 0; /* Rompemos el bucle interno, volvemos a accept() */
                break;

            default:
                sesion_activa = 0; /* Opcode invalido = Abortar sesion */
                break;
            }
        }

        close(socket_cliente);
    }

    /* RUTINA DE LIMPIEZA Y APAGADO
       Si llegamos aca es porque recibimos SIGTERM y daemon_activo = 0 
    */
    unlink("/tmp/accion_senalfebox.pid"); /* Borramos registro de existencia */
    unlink(SB_SOCKET_PATH);               /* Borramos el socket fisico de /tmp */
    close(socket_servidor);

    LOG(STDOUT_FILENO, SB_LOG_INFO, "SIGTERM recibido - daemon terminado limpiamente");

    return EXIT_SUCCESS;
}
