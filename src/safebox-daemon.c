/*
 * safebox-daemon.c
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
 * Daemon de la boveda de archivos cifrados.
 *
 * Syscalls principales:
 *   termios:         lectura segura del password (sin echo)
 *   fork/setsid:     daemonizacion
 *   socket/bind/
 *   listen/accept:   Unix Domain Socket
 *   getsockopt:      SO_PEERCRED (identidad del cliente)
 *   open/mmap/msync: acceso a archivos cifrados
 *   memfd_create:    fd anonimo en RAM para el contenido descifrado
 *   sendmsg:         SCM_RIGHTS (transferir fd al cliente)
 *   opendir/readdir: listar directorio del safebox
 *   unlink:          eliminar archivos
 *   signal:          SIGTERM handler para cierre limpio
 *
 * Compilacion (la hace el Makefile):
 *   gcc -std=c11 -Wall -Wextra -Werror \
 *       -Iinclude \
 *       -o safebox-daemon src/safebox-daemon.c
 *
 * Uso:
 *   ./safebox-daemon ./mi_boveda
 *   safebox password: ****
 *   [safebox] pid=XXXX listo
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

#include "safebox.h"

volatile sig_atomic_t keep_running = 1;

void handle_sigterm(int sig)
{
    (void)sig;
    keep_running = 0;
}

static void read_password(const char *prompt, char *buf, size_t buflen)
{
    printf("%s", prompt);
    fflush(stdout);

    if (isatty(STDIN_FILENO))
    {
        struct termios old_t, new_t;
        tcgetattr(STDIN_FILENO, &old_t);
        new_t = old_t;
        new_t.c_lflag &= ~(tcflag_t)(ECHO | ECHOE | ECHOK | ECHONL);
        tcsetattr(STDIN_FILENO, TCSANOW, &new_t);

        if (fgets(buf, (int)buflen, stdin) == NULL)
            buf[0] = '\0';

        tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
        printf("\n");
    }
    else
    {
        if (fgets(buf, (int)buflen, stdin) == NULL)
            buf[0] = '\0';
    }

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Uso: %s <directorio_boveda>\n", argv[0]);
        return EXIT_FAILURE;
    }

    DIR *dir = opendir(argv[1]);
    if (dir == NULL)
    {
        perror("Error: El directorio de la boveda no existe o no hay permisos");
        return EXIT_FAILURE;
    }
    closedir(dir);

    char master_pwd[MAX_KEY_LEN] = {0};
    read_password("safebox password: ", master_pwd, sizeof(master_pwd));
    if (strlen(master_pwd) == 0)
    {
        fprintf(stderr, "Error: password vacio\n");
        return EXIT_FAILURE;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        exit(EXIT_FAILURE);
    }

    if (pid > 0)
    {
        printf("[safebox] pid=%d listo\n", pid);
        exit(EXIT_SUCCESS);
    }

    setsid();

    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = handle_sigterm;

    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);

    int fd_null = open("/dev/null", O_RDWR);
    if (fd_null != -1)
    {
        dup2(fd_null, STDIN_FILENO);
        close(fd_null);
    }

    int log_fd = open("/tmp/safebox.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd != -1)
    {
        dup2(log_fd, STDOUT_FILENO);
        dup2(log_fd, STDERR_FILENO);
        close(log_fd);
    }

    int pid_fd = open("/tmp/safebox.pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pid_fd != -1)
    {
        char pid_str[32];
        int len = snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
        write(pid_fd, pid_str, len);
        close(pid_fd);
    }

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        LOG(STDOUT_FILENO, SB_LOG_ERROR, "Error: Fallo en la creación del socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SB_SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    unlink(SB_SOCKET_PATH);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        LOG(STDOUT_FILENO, SB_LOG_ERROR, "Error: Fallo en bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) == -1)
    {
        LOG(STDOUT_FILENO, SB_LOG_ERROR, "Error: Fallo en listen");
        exit(EXIT_FAILURE);
    }

    LOG(STDOUT_FILENO, SB_LOG_INFO, "escuchando en %s", SB_SOCKET_PATH);

    while (keep_running)
    {
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);

        if (client_fd == -1)
        {
            if (errno == EINTR)
                continue;
            continue;
        }

        struct ucred cred;
        socklen_t cred_len = sizeof(cred);
        if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0)
        {
            LOG(STDOUT_FILENO, SB_LOG_INFO, "conexion entrante uid=%ld pid=%ld", (long)cred.uid, (long)cred.pid);
        }

        sb_auth_msg_t auth_msg;
        if (recv(client_fd, &auth_msg, sizeof(auth_msg), MSG_WAITALL) != sizeof(auth_msg))
        {
            close(client_fd);
            continue;
        }

        uint32_t expected_hash = sb_djb2(master_pwd);
        if (auth_msg.password_hash != expected_hash)
        {
            LOG(STDOUT_FILENO, SB_LOG_WARN, "autenticacion fallida uid=%ld pid=%ld", (long)cred.uid, (long)cred.pid);

            uint8_t status_error = 1;
            send(client_fd, &status_error, 1, 0);
            close(client_fd);
            continue;
        }

        uint8_t status_ok = SB_OK;
        send(client_fd, &status_ok, 1, 0);
        LOG(STDOUT_FILENO, SB_LOG_OK, "autenticacion exitosa uid=%ld pid=%ld", (long)cred.uid, (long)cred.pid);

        int client_active = 1;
        while (client_active && keep_running)
        {
            uint8_t opcode;
            ssize_t bytes_read = recv(client_fd, &opcode, sizeof(opcode), 0);

            if (bytes_read <= 0)
            {
                break;
            }

            switch (opcode)
            {
            case SB_OP_LIST:
            {
                DIR *d = opendir(argv[1]);
                char list_buf[4096] = {0};
                uint32_t offset = 0;

                if (d)
                {
                    struct dirent *dir_ent;
                    while ((dir_ent = readdir(d)) != NULL)
                    {
                        if (strcmp(dir_ent->d_name, ".") == 0 || strcmp(dir_ent->d_name, "..") == 0)
                            continue;
                        int len = snprintf(list_buf + offset, sizeof(list_buf) - offset, "%s\n", dir_ent->d_name);
                        if (len > 0)
                            offset += len;
                    }
                    closedir(d);
                }

                uint8_t status = SB_OK;
                send(client_fd, &status, sizeof(status), 0);

                uint32_t list_size = offset;
                send(client_fd, &list_size, sizeof(list_size), 0);

                if (list_size > 0)
                {
                    send(client_fd, list_buf, list_size, 0);
                }

                LOG(STDOUT_FILENO, SB_LOG_OK, "LIST completado");
                break;
            }

            case SB_OP_GET:
            {
                char filename[MAX_FNAME_LEN];
                int i = 0;
                while (i < MAX_FNAME_LEN - 1)
                {
                    if (recv(client_fd, &filename[i], 1, 0) <= 0)
                        break;
                    if (filename[i] == '\0')
                        break;
                    i++;
                }
                filename[i] = '\0';

                char filepath[512];
                snprintf(filepath, sizeof(filepath), "%s/%s", argv[1], filename);

                int fd_in = open(filepath, O_RDONLY);
                if (fd_in < 0)
                {
                    uint8_t status = SB_ERR_NOFILE;
                    send(client_fd, &status, 1, 0);
                    LOG(STDOUT_FILENO, SB_LOG_ERROR, "GET %s archivo no encontrado", filename);
                    break;
                }

                struct stat st;
                if (fstat(fd_in, &st) < 0 || st.st_size < (off_t)sizeof(sb_file_header_t))
                {
                    close(fd_in);
                    uint8_t status = SB_ERR_IO;
                    send(client_fd, &status, 1, 0);
                    break;
                }

                void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd_in, 0);
                if (map == MAP_FAILED)
                {
                    close(fd_in);
                    uint8_t status = SB_ERR_IO;
                    send(client_fd, &status, 1, 0);
                    break;
                }

                sb_file_header_t *header = (sb_file_header_t *)map;
                uint32_t expected_payload_size = header->payload_size;
                size_t actual_payload_size = st.st_size - sizeof(sb_file_header_t);

                if (header->version != SB_VERSION || actual_payload_size != expected_payload_size || actual_payload_size < SB_MAGIC_LEN)
                {
                    munmap(map, st.st_size);
                    close(fd_in);
                    uint8_t status = SB_ERR_CORRUPT;
                    send(client_fd, &status, 1, 0);
                    LOG(STDOUT_FILENO, SB_LOG_ERROR, "GET %s archivo corrupto", filename);
                    break;
                }

                char *cipher_data = (char *)map + sizeof(sb_file_header_t);
                char magic[SB_MAGIC_LEN];
                size_t key_len = strlen(master_pwd);

                for (int k = 0; k < SB_MAGIC_LEN; k++)
                {
                    magic[k] = cipher_data[k] ^ master_pwd[k % key_len];
                }

                if (strncmp(magic, SB_MAGIC, SB_MAGIC_LEN) != 0)
                {
                    munmap(map, st.st_size);
                    close(fd_in);
                    uint8_t status = SB_ERR_CORRUPT;
                    send(client_fd, &status, 1, 0);
                    LOG(STDOUT_FILENO, SB_LOG_ERROR, "GET %s archivo corrupto (magic invalido)", filename);
                    break;
                }

                int mem_fd = memfd_create("safebox_content", MFD_CLOEXEC);
                if (mem_fd < 0)
                {
                    munmap(map, st.st_size);
                    close(fd_in);
                    uint8_t status = SB_ERR_IO;
                    send(client_fd, &status, 1, 0);
                    break;
                }

                size_t content_size = actual_payload_size - SB_MAGIC_LEN;
                char *plain = malloc(content_size);
                if (plain)
                {
                    for (size_t k = 0; k < content_size; k++)
                    {
                        plain[k] = cipher_data[SB_MAGIC_LEN + k] ^ master_pwd[(SB_MAGIC_LEN + k) % key_len];
                    }
                    write(mem_fd, plain, content_size);
                    free(plain);
                }

                lseek(mem_fd, 0, SEEK_SET);

                munmap(map, st.st_size);
                close(fd_in);

                struct msghdr msg;
                memset(&msg, 0, sizeof(msg));

                struct iovec iov[1];
                uint8_t status = SB_OK;
                iov[0].iov_base = &status;
                iov[0].iov_len = 1;
                msg.msg_iov = iov;
                msg.msg_iovlen = 1;

                union
                {
                    struct cmsghdr align;
                    char buf[CMSG_SPACE(sizeof(int))];
                } cmsg_buf;
                memset(&cmsg_buf, 0, sizeof(cmsg_buf));

                msg.msg_control = cmsg_buf.buf;
                msg.msg_controllen = sizeof(cmsg_buf.buf);

                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(int));
                memcpy(CMSG_DATA(cmsg), &mem_fd, sizeof(int));

                if (sendmsg(client_fd, &msg, 0) < 0)
                {
                    LOG(STDOUT_FILENO, SB_LOG_ERROR, "error al enviar fd para %s", filename);
                }
                else
                {
                    LOG(STDOUT_FILENO, SB_LOG_OK, "GET %s entregado a pid=%ld", filename, (long)cred.pid);
                }

                close(mem_fd);
                break;
            }

            case SB_OP_PUT:
            {
                char filename[MAX_FNAME_LEN];
                int i = 0;
                while (i < MAX_FNAME_LEN - 1)
                {
                    if (recv(client_fd, &filename[i], 1, 0) <= 0)
                        break;
                    if (filename[i] == '\0')
                        break;
                    i++;
                }
                filename[i] = '\0';

                uint32_t file_size = 0;
                if (recv(client_fd, &file_size, sizeof(uint32_t), MSG_WAITALL) != sizeof(uint32_t))
                    break;

                char filepath[512];
                snprintf(filepath, sizeof(filepath), "%s/%s", argv[1], filename);

                int fd_out = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd_out < 0)
                {
                    uint8_t resp = SB_ERR_IO;
                    send(client_fd, &resp, 1, 0);
                    break;
                }

                sb_file_header_t header;
                header.version = SB_VERSION;
                header.payload_size = file_size + SB_MAGIC_LEN;
                memset(header.reserved, 0, 3);
                write(fd_out, &header, sizeof(header));

                size_t key_len = strlen(master_pwd);
                size_t key_idx = 0;

                char magic[SB_MAGIC_LEN] = "SBX!";
                for (int m = 0; m < SB_MAGIC_LEN; m++)
                {
                    char encrypted_byte = magic[m] ^ master_pwd[key_idx % key_len];
                    write(fd_out, &encrypted_byte, 1);
                    key_idx++;
                }

                char buffer[4096];
                uint32_t bytes_remaining = file_size;
                int io_error = 0;

                while (bytes_remaining > 0)
                {
                    uint32_t to_read = (bytes_remaining < sizeof(buffer)) ? bytes_remaining : sizeof(buffer);
                    ssize_t r = recv(client_fd, buffer, to_read, MSG_WAITALL);
                    if (r <= 0)
                    {
                        io_error = 1;
                        break;
                    }

                    for (ssize_t b = 0; b < r; b++)
                    {
                        buffer[b] ^= master_pwd[key_idx % key_len];
                        key_idx++;
                    }

                    if (write(fd_out, buffer, r) != r)
                    {
                        io_error = 1;
                        break;
                    }
                    bytes_remaining -= r;
                }

                close(fd_out);

                uint8_t status = io_error ? SB_ERR_IO : SB_OK;
                send(client_fd, &status, sizeof(status), 0);

                if (io_error)
                {
                    LOG(STDOUT_FILENO, SB_LOG_ERROR, "error al guardar %s", filename);
                    unlink(filepath);
                }
                else
                {
                    LOG(STDOUT_FILENO, SB_LOG_OK, "PUT %s completado", filename);
                }
                break;
            }

            case SB_OP_DEL:
            {
                char filename[MAX_FNAME_LEN];
                int i = 0;
                while (i < MAX_FNAME_LEN - 1)
                {
                    if (recv(client_fd, &filename[i], 1, 0) <= 0)
                        break;
                    if (filename[i] == '\0')
                        break;
                    i++;
                }
                filename[i] = '\0';

                char filepath[512];
                snprintf(filepath, sizeof(filepath), "%s/%s", argv[1], filename);

                uint8_t status = SB_OK;
                if (unlink(filepath) == -1)
                {
                    status = SB_ERR_NOFILE;
                    LOG(STDOUT_FILENO, SB_LOG_ERROR, "error al eliminar %s", filename);
                }
                else
                {
                    LOG(STDOUT_FILENO, SB_LOG_OK, "DEL %s completado", filename);
                }

                send(client_fd, &status, sizeof(status), 0);
                break;
            }

            case SB_OP_BYE:
                LOG(STDOUT_FILENO, SB_LOG_INFO, "BYE uid=%ld pid=%ld sesion cerrada", (long)cred.uid, (long)cred.pid);
                client_active = 0;
                break;

            default:
                client_active = 0;
                break;
            }
        }

        close(client_fd);
    }

    unlink("/tmp/safebox.pid");
    unlink(SB_SOCKET_PATH);
    close(server_fd);

    LOG(STDOUT_FILENO, SB_LOG_INFO, "SIGTERM recibido");
    LOG(STDOUT_FILENO, SB_LOG_INFO, "daemon terminado limpiamente");

    return EXIT_SUCCESS;
}
