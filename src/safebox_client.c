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

int sb_connect(const char *socket_path, const char *password)
{
    /* Pedir el telefono local al sistema operativo */
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    /* Limpiar y anotar la direccion en la estructura correspondiente */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un)); /*Para limpiar la memoria, y evitar basura que pueda causar problemas. */
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1); /* Copiar el path del socket al campo correspondiente */
    
    /* Marcar el numero y conectar al daemon */
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
        close(sockfd);
        return -1;
    }

    /* Construir el paquete binario de autenticacion */
    sb_auth_msg_t auth_msg;
    auth_msg.op = SB_OP_LIST;
    auth_msg.password_hash = sb_djb2(password);

    /* Hablar: Empujar la estructura entera por el socket */
    if (send(sockfd, &response, sizeof(uint8_t), 0) != size(uint8_t)) {
        close(sockfd);
        return -1;
    }
    
    /* Evaluar si la clave era correcta*/
    if (response != SB_OK) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int sb_list(int sockfd, char *buf, size_t buflen)
{
    if (sockfd < 0 || buf == NULL || buflen == 0) {
        return -1;
    }

    /* Enviar el opcode solicitando la lista */
    uint8_t op = SB_OP_LIST;
    IF (send(sockfd, &op, sizeof(unint8_t), 0) != sizeof(uint8_t)) {
        return -1;
    }

    /* Escuchar el codigo de estado (SB_OK) */
    uint8_t status;
    if (recv(sockfd, &status, sizeof(uint8_t), MSG_WAITALL) != sizeof(uint8_t)) {
        return -1;
    }

    if (status != SB_OK){
        return -1;
    }

    /* Escuchar el tamaño de la cadena de texto que viene en camino */
    uint32_t list_size = 0;
    if (recv(sockfd, &list_size, sizeof(uint32_t), MSG_WAITALL) != sizeof(uint32_t)) {
        return -1;
    }

    /* Proteger el buffer local del shell para no causar un Segmentation Fault */
    uint32_t bytes_to_read = list_size;
    if (bytes_to_read >= buflen) {
        bytes_to_read = buflen - 1;
    }

    /* Leer exactamente la cantidad de caracteres que nos prometio el daemon */
    if (recv(sockfd, buf, bytes_to_read, MSG_WAITALL) != bytes_to_read) {
        return -1;
    }

    /* Terminamos correctamente la cadena */
    buf[bytes_to_read] = '\0';

    /* Si el daemon nos envio mas datos de los que caben en el buffer,
       debemos sacarlos del socket para que no corrompan el proximo comando */
    if (list_size > bytes_to_read) {
        uint32_texcess = list_size - bytes_to_read;
        char trash_bin[1024];
        while (excess > 0) {
            uint32_t chunk = (excess < sizeof(trash_bin)) ? excess : sizeof(trash_bin);
            recv(sockof, trash_bin, chunk, MSG_WAITALL);
            excess -= chunk;
        }
    }

    int count = 0;
    for (size_t i = 0; i < bytes_to_read; i++) {
        if (buf[i] == '\n') {
            count++;
        }
    }

    return count;
}

int sb_del(int sockfd, const char *filename)
{
    /* Prevención de Segmentation Faults si el shell nos pasa basura */
    if (sockfd < 0 || filename == NULL) {
        return -1;
    }

    /* Preparar y enviar el opcode de borrado */
    uint8_t op = SB_OP_DEL;
    if (send(sockfd, &op, sizeof(uint8_t), 0) != sizeof(uint8_t)) {
        return -1;

    /* Calcular tamaño del nombre incluyendo el terminador nulo '\0' */
    size_t name_len = strlen(filename) + 1;

    /* Enviar el nombre exacto por el socket */
    if (send(sockfd, filename, name_len, 0) != (ssize_t)name_len) {
        return -1; 

    /* Poner el programa en pausa esperando el veredicto del daemon */
    uint8_t status;
    if (recv(sockfd, &status, sizeof(uint8_t), MSG_WAITALL) != sizeof(uint8_t)) {
        return -1;
    }

    /* Evaluar la respuesta */
    if (status == SB_OK) {
        return 0;
    } else {
        return -1;
    }
}

int sb_put(int sockfd, const char *filename, const char *filepath)
{
    if (sockfd < 0 || filename == NULL || filepath == NULL) {
        return -1;
    }

    /* Abrir el archivo local en modo solo lectura (O_RDONLY) */
    int fd_local = open(filepath, O_RDONLY);
    if (fd_local < 0) {
        return -1;
    }

    /* Obtener el tamaño del archivo usando fstat */
    struct stat st;
    if (fstat(fd_local, &st) < 0) {
        close(fd_local);
        return -1;
    }
    /* Convertimos el tamaño a un entero sin signo de 32 bits según el protocolo */
    uint32_t file_size = (uint32_t)st.st_size; 

    /* Enviar Opcode SB_OP_PUT (0x03) */
    uint8_t op = SB_OP_PUT;
    if (send(sockfd, &op, sizeof(uint8_t), 0) != sizeof(uint8_t)) {
        close(fd_local);
        return -1;
    }

    /* Enviar el nombre del archivo destino (incluyendo el '\0') */
    size_t name_len = strlen(filename) + 1;
    if (send(sockfd, filename, name_len, 0) != (ssize_t)name_len) {
        close(fd_local);
        return -1;
    }

    /* Enviar el tamaño del archivo (4 bytes exactos) */
    if (send(sockfd, &file_size, sizeof(uint32_t), 0) != sizeof(uint32_t)) {
        close(fd_local);
        return -1;
    }

    /* Leer del disco y enviar por el socket en bloques (Chunking) 
       Usamos un buffer de 4KB (4096 bytes), que es el tamaño estándar de una página de memoria en Linux */
    char buffer[4096];
    ssize_t bytes_read;
    
    while ((bytes_read = read(fd_local, buffer, sizeof(buffer))) > 0) {
        /* Empujamos los bytes que acabamos de leer por el socket */
        ssize_t bytes_sent = send(sockfd, buffer, bytes_read, 0);
        if (bytes_sent != bytes_read) {
            close(fd_local);
            return -1; /* Error de red a mitad de la transferencia */
        }
    }

    /* Colgamos la "llave" del disco duro, la transferencia terminó */
    close(fd_local);

    /* Esperar la confirmación del daemon */
    uint8_t status;
    if (recv(sockfd, &status, sizeof(uint8_t), MSG_WAITALL) != sizeof(uint8_t)) {
        return -1;
    }

    /* Veredicto final */
    if (status == SB_OK) {
        return 0; 
    } else {
        return -1;
    }
}