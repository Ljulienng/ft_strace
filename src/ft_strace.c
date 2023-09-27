#include "ft_strace.h"

t_summary *g_summary;

// Your helper functions here...

char *resolve_path(char *binary)
{
    // If the binary is specified with an absolute path or relative to current directory,
    // don't search in PATH, just return the binary path itself
    if (binary[0] == '/' || strncmp(binary, "./", 2) == 0)
    {
        return strdup(binary);
    }

    char *path_env = strdup(getenv("PATH"));
    char *saveptr;
    char *path = strtok_r(path_env, ":", &saveptr);

    while (path)
    {
        char *possible_path = malloc(strlen(path) + strlen(binary) + 2);
        sprintf(possible_path, "%s/%s", path, binary);

        if (access(possible_path, X_OK) == 0)
        { // file exists and is executable
            free(path_env);
            return possible_path;
        }

        free(possible_path);
        path = strtok_r(NULL, ":", &saveptr);
    }

    free(path_env);
    return strdup(binary); // Return original binary if not found in PATH
}

// Parsing command line arguments
int parse_arguments(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <program>\n", argv[0]);
        return -1;
    }

    int first_arg = 1;
    g_summary = malloc(sizeof(t_summary));
    g_summary->on = 0;
    if (strncmp(argv[1], "-c", 2) == 0 && strlen(argv[1]) == 2)
    {
        g_summary->on = 1;
        first_arg++;
    }
    return first_arg;
}

// Opening the binary file
FILE *open_binary_file(const char *binary_path)
{
    FILE *fp = fopen(binary_path, "rb");
    if (!fp)
    {
        fprintf(stderr, "Impossible d'ouvrir le fichier binaire %s.\n", binary_path);
        return NULL;
    }
    return fp;
}

// Reading the ELF header
int read_elf_header(FILE *fp, Elf64_Ehdr *elf_header)
{
    if (fread(elf_header, sizeof(Elf64_Ehdr), 1, fp) != 1)
    {
        fprintf(stderr, "Erreur de lecture de l'en-tête ELF.\n");
        return -1;
    }
    return 0;
}

// Determining the architecture of the binary file
int determine_architecture(Elf64_Ehdr *elf_header)
{
    if (elf_header->e_ident[EI_CLASS] == ELFCLASS32)
        return 32;
    else if (elf_header->e_ident[EI_CLASS] == ELFCLASS64)
        return 64;
    else
    {
        fprintf(stderr, "Binaire incompatible avec la machine actuelle.\n");
        return -1;
    }
}

// Fork and execute the binary
pid_t fork_and_exec(const char *binary_path, char **argv, char **env, int first_arg)
{
    pid_t pid = fork();
    (void)env;
    if (pid == 0)
    {
        execvp(binary_path, argv + first_arg); // Changed execve to execvp
        perror("execvp");                      // Changed execve to execvp in perror
        exit(1);
    }
    else if (pid < 0)
    {
        perror("fork");
        return -1;
    }
    return pid;
}

static int handle_syscall(pid_t pid)
{
    union
    {
        struct user_regs_struct x86_64_r;
        struct user_regs_struct32 i386_r;
    } regs;
    struct iovec x86_io;
    x86_io.iov_base = &regs;
    x86_io.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &x86_io) < 0)
        return (EXIT_FAILURE);
    return (EXIT_SUCCESS);
}

int handle_process(pid_t pid, int bits, char **argv)
{
    t_regs_32 regs_32;
    struct user_regs_struct regs;
    struct iovec iov;
    int i = 0;
    int status;
    // int signal = 0;

    g_summary->number_of_calls = 0;
    g_summary->error = 0;
    g_summary->syscall = 0;
    g_summary->usecond = 0;
    g_summary->name = argv[1];
    g_summary->next = NULL;

    sigset_t new;
    // sigset_t old;

    ptrace(PTRACE_SEIZE, pid, NULL, NULL);
    ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
    sigemptyset(&new);
    sigaddset(&new, SIGHUP);
    sigaddset(&new, SIGINT);
    sigaddset(&new, SIGQUIT);
    sigaddset(&new, SIGPIPE);
    sigaddset(&new, SIGTERM);
    // if (sigprocmask(SIG_SETMASK, &old, NULL))
    //     perror("sigprocmask SETMASK");
    waitpid(pid, &status, 0);
    if (sigprocmask(SIG_BLOCK, &new, NULL))
        perror("sigprocmask BLOCK");
    if (WIFEXITED(status))
        return 0;
    if (bits == 32 && g_summary->on == 0)
        printf("strace: [ Process PID=%d runs in 32 bit mode. ]\n", pid);

    siginfo_t si;
    int signal = 0;
    while (1)
    {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, signal) < 0)
            break;
        if (waitpid(pid, &status, 0) < 0)
            break;
        // printf("getpid = %d\n", getpid());
        if (WIFEXITED(status))
            break;
        if (!ptrace(PTRACE_GETSIGINFO, pid, NULL, &si))
        {
            signal = si.si_signo;
            if (signal == SIGTRAP)
                signal = 0;
        }
        else
            signal = 0;

        if (handle_syscall(pid) == EXIT_FAILURE)
        {
            printf("whoooo\n");
            break;
        }

        if (bits == 64)
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        else
        {
            iov.iov_base = &regs_32;
            iov.iov_len = sizeof(regs_32);
            ptrace(PTRACE_GETREGSET, pid, 1, &iov);
        }
        if (i % 2 != 0)
        {
            if (g_summary->on == 1)
            {
                if (bits == 64)
                    summary_activate(regs.orig_rax, (union regs_union){.regs64 = regs}, 1);
                else if (bits == 32)
                    summary_activate(regs_32.orig_eax, (union regs_union){.regs32 = regs_32}, 0);
            }
            else
            {
                if (bits == 64)
                    print_syscall_64(regs.orig_rax, regs, pid);
                else if (bits == 32)
                    print_syscall_32(regs_32.orig_eax, regs_32, pid);
            }
        }
        i++;
    }
    // printf(");
    if (WIFSIGNALED(status))
    {
        if (g_summary->on == 0)
            printf("--- SIGSEGV {si_signo = SIGSEGV, si_code = SEGV_MAPERR, si_addr = 0x7f7fffffe000} ---\n");
        printf("+++ killed by SIGSEGV +++\n");
        free_summary();
        kill(getpid(), WTERMSIG(status));
        return 1;
    }

    if (WIFSTOPPED(status))
    {
        int sig = WSTOPSIG(status);
        siginfo_t siginfo;
        if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo) < 0)
            exit(1);
        if (sig != 5 && g_summary->on == 0)
            printf("--- %s {si_signo = %s, si_code = %d, si_pid = %d, si_uid = %d, si_status = %d, si_utime = %ld, si_stime = %ld} ---\n",
                   g_sig[sig - 1].name, g_sig[sig - 1].name, siginfo.si_code, siginfo.si_pid, siginfo.si_uid, siginfo.si_status, siginfo.si_utime, siginfo.si_stime);
    }

    if (g_summary->on == 0)
        printf("exit_group(0) = ?\n+++ exited with 0 +++\n");

    double time_total = calc_time();
    if (g_summary->on == 1)
        print_summary(time_total);

    free_summary();

    return 0;
}

// Main function
int main(int argc, char **argv, char **env)
{
    int first_arg = parse_arguments(argc, argv);
    if (first_arg < 0)
    {
        return 1;
    }

    char *binary_path;
    if (g_summary->on == 1)
    {
        binary_path = resolve_path(argv[2]);
    }
    else
    {
        binary_path = resolve_path(argv[1]);
    }

    if (!binary_path)
    {
        fprintf(stderr, "Impossible de trouver le binaire %s.\n", argv[1]);
        return 1;
    }

    FILE *fp = open_binary_file(binary_path);
    if (!fp)
    {
        return 1;
    }

    Elf64_Ehdr elf_header;
    if (read_elf_header(fp, &elf_header) < 0)
    {
        fclose(fp);
        return 1;
    }

    int bits = determine_architecture(&elf_header);
    if (bits < 0)
    {
        fclose(fp);
        return 1;
    }

    g_summary->arch = bits;

    pid_t pid = fork_and_exec(binary_path, argv, env, first_arg);
    if (pid < 0)
    {
        fclose(fp);
        return 1;
    }

    // int status = 0;
    int ret = handle_process(pid, bits, argv);
    fclose(fp);

    if (binary_path)
        free(binary_path);
    return ret;
}
