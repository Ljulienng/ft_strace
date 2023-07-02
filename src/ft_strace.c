#include "ft_strace.h"

t_summary *g_summary;
void print_summarry(double time)
{
	printf("%% time     seconds  usecs/call     calls    errors syscall\n------- ----------- ----------- --------- --------- ----------------\n");
	t_summary *tmp = g_summary;
	tmp = tmp->next;
	int syscall_total = 1;
	int error_total = 0;
	while (tmp)
	{
		printf("%6.2f", calc_pourcent(tmp->seconds, time));
		printf("%14.6f", tmp->seconds);
		printf("%11lld", tmp->usecond);
		printf("%11d", tmp->number_of_calls);
		if (tmp->error == 0)
			printf("          ");
		else
			printf("%10d", tmp->error);
		if (g_summary->arch == 64)
			printf(" %s\n", g_syscall[tmp->syscall].name);
		else
		{
			int count = 0;
			while (g_syscall[count].code32 && g_syscall[count].code32 != tmp->syscall)
				count++;
			printf(" %s\n", g_syscall[count].name);
		}
		syscall_total = syscall_total + tmp->number_of_calls;
		error_total = error_total + tmp->error;
		tmp = tmp->next;
	}
	printf("------- ----------- ----------- --------- --------- ----------------\n");
	printf("100.00    %9.6f                    %2d%10d total\n", time, syscall_total, error_total);
	return;
}

void free_summary()
{
	t_summary *temp;
	while (g_summary->next)
	{
		temp = g_summary;
		g_summary = g_summary->next;
		free(temp);
	}
	free(g_summary);
	return;
}

int main(int argc, char **argv, char **env)
{
	pid_t pid;
	int status;
	struct user_regs_struct regs;
	int i = 0;
	struct iovec iov;
	t_regs_32 regs_32;

	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <program>\n", argv[0]);
		return 1;
	}
	int first_arg = 1;
	g_summary = malloc(sizeof(t_summary));
	g_summary->on = 0;
	if (strncmp(argv[1], "-c", 2) == 0 && strlen(argv[1]) == 2)
	{
		g_summary->on = 1;
		first_arg++;
	}

	int tota_size = 0;
	for (int i = 1; i < argc; i++)
	{
		tota_size += strlen(argv[i]) + 1;
	}

	// Allouer de la mémoire pour la chaîne
	char *chaine = (char *)malloc(sizeof(char) * tota_size + 100);
	chaine[0] = '\0';
	strcat(chaine, "[");
	// Concaténer les arguments dans la chaîne
	for (int i = 1; i < argc; i++)
	{
		strcat(chaine, "\"");
		strcat(chaine, argv[i]);
		strcat(chaine, "\", ");
	}
	chaine[strlen(chaine) - 2] = ']';
	chaine[strlen(chaine) - 1] = '\0';
	const char *binary_path = NULL;
	if (g_summary->on == 1)
		binary_path = argv[2];
	else
		binary_path = argv[1];

	FILE *fp = fopen(binary_path, "rb");
	if (!fp)
	{
		fprintf(stderr, "Impossible d'ouvrir le fichier binaire %s.\n", binary_path);
		free(chaine);
		return 1;
	}

	// Lecture de l'en-tête ELF pour déterminer si le binaire est en 32 bits ou en 64 bits
	Elf64_Ehdr elf_header;
	if (fread(&elf_header, sizeof(elf_header), 1, fp) != 1)
	{
		fprintf(stderr, "Erreur de lecture de l'en-tête ELF.\n");
		fclose(fp);
		free(chaine);
		return 1;
	}

	int bits = 0;
	if (elf_header.e_ident[EI_CLASS] == ELFCLASS32)
		bits = 32;
	else if (elf_header.e_ident[EI_CLASS] == ELFCLASS64)
		bits = 64;
	else
	{
		// printf("%d, %d, %d\n", elf_header.e_ident[EI_CLASS], ELFCLASS32, ELFCLASS64);
		fprintf(stderr, "Binaire incompatible avec la machine actuelle.\n");
		fclose(fp);
		free(chaine);
		return 1;
	}
	g_summary->arch = bits;
	g_summary->number_of_calls = 0;
	g_summary->error = 0;
	g_summary->syscall = 0;
	g_summary->usecond = 0;
	g_summary->name = argv[1];
	g_summary->next = NULL;
	pid = fork();
	if (pid == 0)
	{
		execve(binary_path, argv + first_arg, env);
		perror("execve");
		exit(1);
	}
	else if (pid < 0)
	{
		perror("fork");
		exit(1);
	}
	if (pid > 0)
	{
		sigset_t new;
		sigset_t old;

		ptrace(PTRACE_SEIZE, pid, NULL, NULL);
		ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
		sigemptyset(&new);
		sigaddset(&new, SIGHUP);
		sigaddset(&new, SIGINT);
		sigaddset(&new, SIGQUIT);
		sigaddset(&new, SIGPIPE);
		sigaddset(&new, SIGTERM);
		if (sigprocmask(SIG_SETMASK, &old, NULL))
			perror("sigprocmask SETMASK");
		waitpid(pid, &status, 0);
		if (sigprocmask(SIG_BLOCK, &new, NULL))
			perror("sigprocmask BLOCK");
		if (WIFEXITED(status))
		{
			return 0;
		}
		if (bits == 32 && g_summary->on == 0)
			printf("strace: [ Process PID=%d runs in 32 bit mode. ]\n", pid);
		while (1)
		{
			ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
			waitpid(pid, &status, 0);
			if (WIFEXITED(status))
			{
				break;
			}
			if (WIFSTOPPED(status))
			{
				int sig = WSTOPSIG(status);
				siginfo_t siginfo;
				if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo) < 0)
				{
					perror("ptrace GETSIGINFO");
					exit(1);
				}
				if (sig != 5 && g_summary->on == 0)
					printf("--- %s {si_signo = %s, si_code = %d, si_pid = %d, si_uid = %d, si_status = %d, si_utime = %ld, si_stime = %ld} ---\n",
						   g_sig[sig - 1].name, g_sig[sig - 1].name, siginfo.si_code, siginfo.si_pid, siginfo.si_uid, siginfo.si_status, siginfo.si_utime, siginfo.si_stime);
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
		if (g_summary->on == 0)
			printf("exit_group(0) = ?\n+++ exited with 0 +++\n");
	}
	free(chaine);
	double time_total;
	time_total = calc_time();
	if (g_summary->on == 1)
		print_summarry(time_total);
	free_summary();
	fclose(fp);
	return 0;
}