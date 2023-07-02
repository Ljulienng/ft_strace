#include "ft_strace.h"

void print_read_args_32(pid_t pid, t_regs_32 regs)
{
	unsigned int i;
	long data;
	char buf[4096];

	memset(buf, 0, sizeof(buf));
	i = 0;
	do
	{
		data = ptrace(PTRACE_PEEKDATA, pid, regs.ecx + i, NULL);
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

void summary_activate_32(unsigned long sys, t_regs_32 regs)
{
	int i = 0;
	int count = 0;
	while (g_syscall[count].code32 && g_syscall[count].code32 != sys)
		count++;
	struct timeval start, end;
	gettimeofday(&start, NULL);

	while (i < 6)
	{
		if (g_syscall[count].arg[i] != 0 && i > 0)
		{
		};
		if (g_syscall[count].arg[i] == 1)
		{
		};
		if (g_syscall[count].arg[i] == 2)
		{
		};
		if (g_syscall[count].arg[i] == 3)
		{
			if (sys == SYS_access)
			{
			};
		}
		if (g_syscall[count].arg[i] == 4)
		{
			if (sys == SYS_access)
			{
			};
		}
		if (g_syscall[count].arg[i] == 5)
		{
		};
		i++;
	}

	gettimeofday(&end, NULL);
	long long elapsed_time = time_in_microseconds(start, end);
	// printf("Le temps écoulé est de %lld microsecondes.\n", elapsed_time);
	if (g_syscall[count].ret != 5 && (int)regs.eax < 0)
	{
		if (check_summary(sys, 1) == 1)
		{
			return;
		}
		else
			ft_lstadd_back(&g_summary, ft_fill_summary(1, 1, sys, elapsed_time));
	}
	else
	{
		if (check_summary(sys, 0) == 1)
		{
			return;
		}
		else
			ft_lstadd_back(&g_summary, ft_fill_summary(1, 0, sys, elapsed_time));
	}
	return;
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
				print_read_args_32(pid, regs);
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
				print_read_args_32(pid, regs);
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

void print_read_args(pid_t pid, struct user_regs_struct regs)
{
	unsigned int i;
	long data;
	char buf[4096];
	// size_t nread;
	// if (regs.rdx <= sizeof(buf)) {
	//     nread = regs.rdx;
	// } else {
	//     nread = sizeof(buf);
	// }
	memset(buf, 0, sizeof(buf));
	i = 0;
	do
	{
		data = ptrace(PTRACE_PEEKDATA, pid, regs.rsi + i, NULL);
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

void print_syscall_64(unsigned long sys, struct user_regs_struct regs, int pid)
{

	if (strncmp("exit_group", g_syscall[sys].name, 10) == 0)
		return;
	if (sys == 59)
		return;
	printf("%s(", g_syscall[sys].name);
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
				print_read_args(pid, regs);
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
				print_read_args(pid, regs);
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

void summary_activate_64(unsigned long sys, struct user_regs_struct regs)
{
	int i = 0;
	struct timeval start, end;
	gettimeofday(&start, NULL);

	while (i < 6)
	{
		if (g_syscall[sys].arg[i] != 0 && i > 0)
		{
		};
		if (g_syscall[sys].arg[i] == 1)
		{
		};
		if (g_syscall[sys].arg[i] == 2)
		{
		};
		if (g_syscall[sys].arg[i] == 3)
		{
			if (sys == SYS_access)
			{
			};
		}
		if (g_syscall[sys].arg[i] == 4)
		{
			if (sys == SYS_access)
			{
			};
		}
		if (g_syscall[sys].arg[i] == 5)
		{
		};
		i++;
	}

	gettimeofday(&end, NULL);
	long long elapsed_time = time_in_microseconds(start, end);
	// printf("Le temps écoulé est de %lld microsecondes.\n", elapsed_time);
	if (g_syscall[sys].ret != 5 && (int)regs.rax < 0)
	{
		if (check_summary(sys, 1) == 1)
		{
			return;
		}
		else
			ft_lstadd_back(&g_summary, ft_fill_summary(1, 1, sys, elapsed_time));
	}
	else
	{
		if (check_summary(sys, 0) == 1)
		{
			return;
		}
		else
			ft_lstadd_back(&g_summary, ft_fill_summary(1, 0, sys, elapsed_time));
	}
	return;
}

static int ft_count(unsigned long n)
{
	int i;

	i = 0;
	if (n == 0)
	{
		i = 1;
		return (i);
	}
	while (n)
	{
		n = n / 10;
		i++;
	}
	return (i);
}

char *ft_strrev(char *str)
{
	int i;
	int y;
	char *tmp;

	y = 0;
	i = 0;
	while (str[i] != '\0')
		i++;
	tmp = (char *)malloc(sizeof(char) * (i + 1));
	if (tmp == NULL)
		return (0);
	i--;
	while (i >= 0)
	{
		tmp[y] = str[i];
		i--;
		y++;
	}
	tmp[y] = '\0';
	return (tmp);
}

char *ft_itoa(unsigned long n, int base)
{
	char *alpha;
	char *str;
	char *test;
	int i;

	i = 0;
	str = (char *)malloc(sizeof(char) * (ft_count(n) + 1));
	if (str == NULL)
		return (0);
	alpha = "0123456789abcdef";
	while (n > 0)
	{
		str[i] = alpha[n % base];
		i++;
		n = n / base;
	}
	str[i] = '\0';
	test = ft_strrev(str);
	free(str);
	return (test);
}

double calc_pourcent(double valeur, double total)
{
	double pourcentage = (valeur / total) * 100;
	return pourcentage;
}

void ft_lstadd_back(t_summary **alst, t_summary *new)
{
	t_summary *lst;

	lst = *alst;
	if (*alst == NULL)
		*alst = new;
	else
	{
		while (lst->next)
			lst = lst->next;
		lst->next = new;
	}
}

t_summary *ft_fill_summary(int nb, int error, int sys, long long time)
{
	t_summary *lst = malloc(sizeof(t_summary));

	lst->arch = 0;
	lst->number_of_calls = nb;
	lst->error = error;
	lst->syscall = sys;
	lst->usecond = time;
	lst->next = NULL;
	return lst;
}

int check_summary(unsigned long sys, int error)
{
	t_summary *tmp = g_summary;
	int i = 0;
	while (tmp)
	{
		if (tmp->syscall == sys)
		{
			tmp->number_of_calls++;
			if (error == 1)
				tmp->error = tmp->error + 1;
			return 1;
		}
		tmp = tmp->next;
		i++;
	}
	return 0;
}

long long time_in_microseconds(struct timeval start_time, struct timeval end_time)
{
	long long start_in_microseconds = start_time.tv_sec * 1000000LL + start_time.tv_usec;
	long long end_in_microseconds = end_time.tv_sec * 1000000LL + end_time.tv_usec;
	return end_in_microseconds - start_in_microseconds;
}

double microseconds_to_seconds(long long microseconds)
{
	return (double)microseconds / 1000000.0;
}

double calc_time()
{
	t_summary *tmp = g_summary;
	int i = 0;
	double time_total = 0;
	while (tmp)
	{
		tmp->seconds = microseconds_to_seconds(tmp->usecond) * tmp->number_of_calls;
		time_total = time_total + tmp->seconds;
		tmp = tmp->next;
		i++;
	}
	return time_total;
}