/*
 * safebox_client.c
 *
 * CI3825 - Sistemas de Operacion I
 * Proyecto 3 - SafeBox
 *
 * ╔══════════════════════════════════════════════════════╗
 * ║  ARCHIVO A IMPLEMENTAR POR LOS ESTUDIANTES           ║
 * ║  Este es el codigo de REFERENCIA del profesor.       ║
 * ║  Los estudiantes entregaran su propia version.       ║
 * ╚══════════════════════════════════════════════════════╝
 *
 * Implementa las funciones declaradas en safebox_client.h.
 * Este archivo es la "biblioteca de enlace" entre el
 * minishell (safebox-shell.c) y el daemon.
 *
 * Syscalls principales usadas:
 *   socket(2), connect(2), send(2), recv(2)
 *   sendmsg(2), recvmsg(2) con SCM_RIGHTS
 *   open(2), read(2), fstat(2)
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>

#include "safebox.h"
#include "safebox_client.h"

/**
 * @brief Establece la conexión con el daemon de la bóveda y realiza la autenticación.
 *
 * Crea un socket de dominio UNIX, se conecta a la ruta especificada y envía
 * un mensaje de autenticación utilizando el hash DJB2 de la contraseña proporcionada.
 * Espera la confirmación del daemon (SB_OK) para dar por válida la sesión.
 *
 * @param socket_path Ruta en el sistema de archivos hacia el socket UNIX del daemon.
 * @param password Contraseña en texto plano para autenticarse.
 * @return int El descriptor del socket (fd) conectado si es exitoso, o -1 en caso de error.
 */
int sb_connect(const char *socket_path, const char *password)
{
    /* Solicitamos al sistema operativo un canal de comunicacion local (socket) */
    int socket_cliente = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_cliente < 0)
        return -1;

    /* Preparamos la direccion fisica del daemon en el sistema de archivos */
    struct sockaddr_un direccion_servidor;
    memset(&direccion_servidor, 0, sizeof(struct sockaddr_un));
    direccion_servidor.sun_family = AF_UNIX;

    /* Copiamos la ruta de forma segura para evitar desbordamientos de memoria */
    strncpy(direccion_servidor.sun_path, socket_path, sizeof(direccion_servidor.sun_path) - 1);

    /* Intentamos establecer la conexion con el daemon */
    if (connect(socket_cliente, (struct sockaddr *)&direccion_servidor, sizeof(struct sockaddr_un)) == -1)
    {
        close(socket_cliente);
        return -1;
    }

    /* Construimos el mensaje de seguridad con el hash de la clave */
    sb_auth_msg_t mensaje_autenticacion;
    mensaje_autenticacion.op = 0; /* Opcode dummy para el saludo */
    mensaje_autenticacion.password_hash = sb_djb2(password);

    /* Enviamos nuestras credenciales por el socket */
    if (send(socket_cliente, &mensaje_autenticacion, sizeof(mensaje_autenticacion), 0) != sizeof(mensaje_autenticacion))
    {
        close(socket_cliente);
        return -1;
    }

    /* Esperamos la confirmacion del daemon, MSG_WAITALL garantiza que leamos el byte completo */
    uint8_t status;
    if (recv(socket_cliente, &status, sizeof(uint8_t), MSG_WAITALL) != sizeof(uint8_t) || status != SB_OK)
        return -1;

    /* Autenticacion exitosa, retornamos el descriptor para que el shell lo use */
    return socket_cliente;
}

/**
 * @brief Solicita al daemon la lista de archivos almacenados en la bóveda.
 *
 * Envía el código de operación SB_OP_LIST. Recibe primero el estado y el tamaño
 * total de la lista, para luego leer los nombres de los archivos en bloques
 * protegiendo el buffer local contra desbordamientos.
 *
 * @param sockfd Descriptor del socket conectado al daemon.
 * @param buf Buffer de memoria local donde se guardará la lista recibida como un string.
 * @param buflen Tamaño máximo del buffer (incluyendo el espacio para el terminador nulo).
 * @return int La cantidad de bytes leídos y almacenados en el buffer, o -1 en caso de error.
 */
int sb_list(int sockfd, char *buf, size_t buflen)
{
    /* validaciones basicas de seguridad para evitar Segmentation Faults */
    if (sockfd < 0 || buf == NULL || buflen == 0)
        return -1;

    /* Enviamos el codigo de operacion para listar */
    uint8_t op = SB_OP_LIST;
    if (send(sockfd, &op, sizeof(uint8_t), 0) != sizeof(uint8_t))
        return -1;

    /* Eldaemon nos indica de antemano cuantos bytes mide la lista completa */
    uint8_t status;
    if (recv(sockfd, &status, sizeof(uint8_t), MSG_WAITALL) != sizeof(uint8_t) || status != SB_OK)
        return -1;

    /* Protegemos el buffer local truncando la lectura si el daemon envia mas de lo que cabe */
    uint32_t tamano_total_lista = 0;
    if (recv(sockfd, &tamano_total_lista, sizeof(uint32_t), MSG_WAITALL) != sizeof(uint32_t))
        return -1;

    uint32_t bytes_a_leer = tamano_total_lista;
    if (bytes_a_leer >= buflen)
    {
        bytes_a_leer = buflen - 1; /* Dejamos 1 byte reservado para le finalizador nulo */
    }

    /* Lememos exactamente la porcion de texto calculada */
    if (bytes_a_leer > 0)
    {
        if (recv(sockfd, buf, bytes_a_leer, MSG_WAITALL) != bytes_a_leer)
            return -1;
    }

    /* Aseguramos que el string este correctamente terminado */
    buf[bytes_a_leer] = '\0';

    return bytes_a_leer;
}

/**
 * @brief Solicita al daemon la eliminación de un archivo específico de la bóveda.
 *
 * Envía el código de operación SB_OP_DEL seguido del nombre del archivo
 * que se desea borrar. Espera la confirmación del daemon sobre el éxito de la operación.
 *
 * @param sockfd Descriptor del socket conectado al daemon.
 * @param filename Nombre del archivo dentro de la bóveda que se desea eliminar.
 * @return int 0 si el archivo fue eliminado exitosamente, o -1 en caso de error.
 */
int sb_del(int sockfd, const char *filename)
{
    if (sockfd < 0 || filename == NULL)
    {
        return -1;
    }

    /* Avisamos al daemon que queremos borrar un archivo */
    uint8_t codigo_operacion = SB_OP_DEL;
    if (send(sockfd, &codigo_operacion, sizeof(uint8_t), 0) != sizeof(uint8_t))
        return -1;

    /* Calculamos la longitud del nombre asegurandonos de inculuir el byte nulo '\0' */
    size_t longitud_nombre = strlen(filename) + 1;

    /* Enviamos el nombre completo */
    if (send(sockfd, filename, longitud_nombre, 0) != (ssize_t)longitud_nombre)
        return -1;

    /* Esperamos el veredicto para saber si el archivo se elimino correctamente */
    uint8_t status;
    if (recv(sockfd, &status, sizeof(uint8_t), MSG_WAITALL) != sizeof(uint8_t) || status != SB_OK)
        return -1;

    return 0;
}

/**
 * @brief Envía un archivo local al daemon para que sea cifrado y guardado en la bóveda.
 *
 * Abre el archivo local indicado, extrae su tamaño y envía la petición SB_OP_PUT.
 * Luego transfiere el contenido del archivo a través de la red en fragmentos (chunks)
 * de 4KB para evitar sobrecargar la memoria, esperando finalmente la confirmación del daemon.
 *
 * @param sockfd Descriptor del socket conectado al daemon.
 * @param filename Nombre con el que se guardará el archivo dentro de la bóveda.
 * @param filepath Ruta local del archivo en el disco duro del cliente que será enviado.
 * @return int 0 si la transferencia y el cifrado fueron exitosos, o -1 en caso de error.
 */
int sb_put(int sockfd, const char *filename, const char *filepath)
{
    if (sockfd < 0 || filename == NULL || filepath == NULL)
        return -1;

    /* Abrimos el archivo del disco duro de la computadora en modo lectura */
    int archivo_local = open(filepath, O_RDONLY);
    if (archivo_local < 0)
        return -1; /* Archivo no existe o faltan permisos */

    /* Extraemos informacion del archivo para conocer su peso exacto */
    struct stat info_archivo;
    if (fstat(archivo_local, &info_archivo) < 0)
    {
        close(archivo_local);
        return -1;
    }
    uint32_t tamano_archivo = (uint32_t)info_archivo.st_size;

    /* Comenzamos el protocolo de envio con el Opcode correspondiente */
    uint8_t codigo_operacion = SB_OP_PUT;
    if (send(sockfd, &codigo_operacion, sizeof(uint8_t), 0) != sizeof(uint8_t))
    {
        close(archivo_local);
        return -1;
    }

    /* Enviamos el nombre que tendra en la boveda (incluyendo el terminador '\0') */
    size_t longitud_nombre = strlen(filename) + 1;
    if (send(sockfd, filename, longitud_nombre, 0) != (ssize_t)longitud_nombre)
    {
        close(archivo_local);
        return -1;
    }

    /* Enviamos el peso del archivo (4 bytes exactos) */
    if (send(sockfd, &tamano_archivo, sizeof(uint32_t), 0) != sizeof(uint32_t))
    {
        close(archivo_local);
        return -1;
    }

    /* Leemos el archivo del disco en fragmentos de 4KB y los enciamos por la red */
    char buffer[4096];
    ssize_t bytes_leidos;

    while ((bytes_leidos = read(archivo_local, buffer, sizeof(buffer))) > 0)
    {
        ssize_t total_enviado = 0;

        /* Garantizamos que el bloque completo sea empujado por el socket antes de leer mas disco */
        while (total_enviado < bytes_leidos)
        {
            ssize_t s = send(sockfd, buffer + total_enviado, bytes_leidos - total_enviado, 0);
            if (s <= 0)
            {
                close(archivo_local);
                return -1; /* Falla critica de conexion a mitad de transferencia */
            }
            total_enviado += s;
        }
    }
    close(archivo_local); /* Transferencia finalizada, cerramos el archivo local */

    /* Revisamos si el daemon logro cifrar y guardar todo con exito */
    uint8_t status;
    if (recv(sockfd, &status, sizeof(uint8_t), MSG_WAITALL) != sizeof(uint8_t))
    {
        return -1;
    }

    return (status == SB_OK) ? 0 : -1;
}

/**
 * @brief Cierra la sesión activa con el daemon de forma limpia.
 *
 * Envía el código de operación SB_OP_BYE al daemon para notificar la
 * desconexión inminente y luego cierra el descriptor del socket local.
 *
 * @param sockfd Descriptor del socket conectado al daemon.
 */
void sb_bye(int sockfd)
{
    /* Nos despedimos del daemon formalmente para que cierre su lado de la conexion */
    uint8_t codigo_operacion = SB_OP_BYE;
    send(sockfd, &codigo_operacion, sizeof(uint8_t), 0);
    close(sockfd); /* cerramos nuestro lado de la comunicacion */
}

/**
 * @brief Solicita un archivo de la bóveda y recibe su descriptor de archivo descifrado en RAM.
 *
 * Envía la petición SB_OP_GET con el nombre del archivo. Utiliza la llamada al
 * sistema `recvmsg` configurada con la estructura `msghdr` y `cmsghdr` para
 * extraer los metadatos de control (SCM_RIGHTS) inyectados por el kernel,
 * obteniendo así un file descriptor válido que apunta al contenido en texto claro.
 *
 * @param sockfd Descriptor del socket conectado al daemon.
 * @param filename Nombre del archivo que se desea extraer de la bóveda.
 * @return int El descriptor de archivo (fd) apuntando al contenido descifrado en RAM, o -1 en caso de error.
 */
int sb_get(int sockfd, const char *filename)
{
    if (sockfd < 0 || filename == NULL)
        return -1;

    /* Iniciamos la peticion GET y enviamos el nombre del archivo buscado */
    uint8_t codigo_operacion = SB_OP_GET;
    if (send(sockfd, &codigo_operacion, sizeof(uint8_t), 0) != sizeof(uint8_t))
        return -1;

    size_t longitud_nombre = strlen(filename) + 1;
    if (send(sockfd, filename, longitud_nombre, 0) != (ssize_t)longitud_nombre)
        return -1;

    /* Preparamos el sobre complejo (msghdr) para recibir datos y metadata del kernel */
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    /* Preparamos el compartimiento para el dato normal (el byte de confirmacion SB_OK) */
    struct iovec vector_datos[1];
    uint8_t status;
    vector_datos[0].iov_base = &status;
    vector_datos[0].iov_len = sizeof(status);
    msg.msg_iov = vector_datos;
    msg.msg_iovlen = 1;

    /* Preparamos el compartimiento de control donde el kernel inyectara el File Descriptor.
       Utilizamos unicon para forzar la correcta alineacion de la memoria y evitar cuelgues. */
    union
    {
        struct cmsghdr alineacion_forzada;
        char buffer_crudo[CMSG_SPACE(sizeof(int))];
    } buffer_alineado;
    memset(&buffer_alineado, 0, sizeof(buffer_alineado));

    msg.msg_control = buffer_alineado.buffer_crudo;
    msg.msg_controllen = sizeof(buffer_alineado.buffer_crudo);

    /* Recibimos el paquete utilizando la syscall avanzada recvmsg */
    if (recvmsg(sockfd, &msg, MSG_WAITALL) <= 0)
        return -1;

    /* Si el daemon responde algo distinto a SB_OK, el archivo no existe o hubo conrupcion */
    if (status != SB_OK)
        return -1;

    /* Extraemos la metadata de control del sobre */
    struct cmsghdr *cabecera_control = CMSG_FIRSTHDR(&msg);

    /* Verificamos que el paquete realmente contenga "Derechos" (SMC_RIGTHS) que representan al FD */
    if (cabecera_control != NULL && cabecera_control->cmsg_level == SOL_SOCKET && cabecera_control->cmsg_type == SCM_RIGHTS)
    {
        int descriptor_recibido;
        /* Copiamos el descriptor de archivo de forma segura desde la memoria del kernel a nuestra variable */
        memcpy(&descriptor_recibido, CMSG_DATA(cabecera_control), sizeof(int));
        return descriptor_recibido;
    }

    /* Error de protocolo si no llego ningun descriptor */
    return -1;
}