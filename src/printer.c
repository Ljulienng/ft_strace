#include "ft_strace.h"

void print_read_args(pid_t pid, union regs_union regs, int is_64bit)
{
	unsigned int i;
	long data;
	char buf[4096];

	memset(buf, 0, sizeof(buf));
	i = 0;
	do
	{
		data = ptrace(PTRACE_PEEKDATA, pid, (is_64bit ? regs.regs64.rsi : regs.regs32.ecx) + i, NULL);
		if (data == -1)
		{
			perror("ptrace");
			return;
		}
		memcpy(buf + i, &data, sizeof(long));
		i += sizeof(long);
	} while (i < sizeof(buf) && *(buf + i - 1) != '\0');
	printf("\"%s\"", buf);
}

void print_syscall_32(unsigned long sys, t_regs_32 regs, int pid)
{
	if (sys == 11)
		return;
	int count = 0;
	while (g_syscall[count].code32 && g_syscall[count].code32 != sys)
		count++;
	if (strncmp("exit_group", g_syscall[count].name, 10) == 0)
		return;
	printf("%s(", g_syscall[count].name);
	int i = 0;
	int e = 0;
	char buf[100000];
	long data = 0;
	long long arg_registre[6] = {regs.ebx, regs.ecx, regs.edx, regs.esi, regs.edi, regs.ebp};

	while (i < 6)
	{
		if (g_syscall[count].arg[i] != 0 && i > 0)
			printf(", ");
		if (g_syscall[count].arg[i] == 1)
		{
			printf("%d", (int)arg_registre[i]);
		}
		if (g_syscall[count].arg[i] == 2)
		{
			printf("%u", (unsigned int)arg_registre[i]);
		}
		if (g_syscall[count].arg[i] == 3)
		{
			if (sys == 33)
			{
				do
				{
					data = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)regs.ebx + e, NULL);
					if (data == -1)
					{
						perror("ptrace");
						return;
					}
					buf[e] = data;
					e++;
				} while (data && e < 100000);
				printf("\"%s\"", buf);
				e = 0;
			}
			else
			{
				print_read_args(pid, (union regs_union){.regs32 = regs}, 0);
			}
		}
		if (g_syscall[count].arg[i] == 4)
		{
			if (sys == 33)
			{
				do
				{
					data = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)regs.ebx + e, NULL);
					if (data == -1)
					{
						perror("ptrace");
						return;
					}
					buf[e] = data;
					e++;
				} while (data && e < 100000);
				printf("\"%s\"", buf);
				e = 0;
			}
			else
			{
				print_read_args(pid, (union regs_union){.regs32 = regs}, 0);
			}
		}
		if (g_syscall[count].arg[i] == 5)
		{
			if ((void *)arg_registre[i] == NULL)
				printf("NULL");
			else
				printf("%p", (void *)arg_registre[i]);
		}
		i++;
	}
	if (sys == 0)
		printf("%s", "<... resuming interrupted nanosleep ...>");
	if (g_syscall[count].ret == 5)
	{
		char *str = ft_itoa(regs.eax, 16);
		printf(") = 0x%s\n", str);
		free(str);
	}
	else
	{
		if (sys == 4)
			printf(") = %u\n", regs.edx);
		else
			printf(") = %d\n", (int)regs.eax);
	}
	return;
}

void print_syscall_64(unsigned long sys, struct user_regs_struct regs, int pid)
{

	if (strncmp("exit_group", g_syscall[sys].name, 10) == 0)
		return;
	if (sys == 59)
		return;
	printf("%ld: %s(", sys, g_syscall[sys].name);
	int i = 0;
	int e = 0;
	char buf[100000];
	long data = 0;
	long long arg_registre[6] = {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9};

	while (i < 6)
	{
		if (g_syscall[sys].arg[i] != 0 && i > 0)
			printf(", ");
		if (g_syscall[sys].arg[i] == 1)
		{
			printf("%d", (int)arg_registre[i]);
		}
		if (g_syscall[sys].arg[i] == 2)
		{
			printf("%u", (unsigned int)arg_registre[i]);
		}
		if (g_syscall[sys].arg[i] == 3)
		{
			if (sys == SYS_access || sys == SYS_open)
			{
				do
				{
					data = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rdi + e, NULL);
					if (data == -1)
					{
						perror("ptrace");
						return;
					}
					buf[e] = data;
					e++;
				} while (data && e < 100000);
				printf("\"%s\"", buf);
				e = 0;
			}
			else
			{
				print_read_args(pid, (union regs_union){.regs64 = regs}, 1);
			}
		}
		if (g_syscall[sys].arg[i] == 4)
		{
			if (sys == SYS_access)
			{
				do
				{
					data = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rdi + e, NULL);
					if (data == -1)
					{
						perror("ptrace");
						return;
					}
					buf[e] = data;
					e++;
				} while (data && e < 100000);
				printf("\"%s\"", buf);
				e = 0;
			}
			else
			{
				print_read_args(pid, (union regs_union){.regs64 = regs}, 1);
			}
		}
		if (g_syscall[sys].arg[i] == 5)
		{
			if ((void *)arg_registre[i] == NULL)
				printf("NULL");
			else
				printf("%p", (void *)arg_registre[i]);
		}
		i++;
	}
	if (sys == SYS_restart_syscall)
		printf("%s", "<... resuming interrupted nanosleep ...>");
	if (g_syscall[sys].ret == 5)
	{
		char *str = ft_itoa(regs.rax, 16);
		printf(") = 0x%s\n", str);
		free(str);
	}
	else
	{
		if (regs.orig_rax == SYS_write)
			printf(") = %llu\n", regs.rdx);
		else
			printf(") = %d\n", (int)regs.rax);
	}
	return;
}