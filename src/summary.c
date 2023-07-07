#include "ft_strace.h"

void summary_activate(unsigned long sys, union regs_union regs, int is_64bit)
{
	{
		int i = 0;
		unsigned long count = sys;
		// Determine the system call number for the 32-bit case
		if (!is_64bit)
		{
			count = 0;
			while (g_syscall[count].code32 && g_syscall[count].code32 != sys)
				count++;
		}

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

		int ret_val = is_64bit ? (int)regs.regs64.rax : (int)regs.regs32.eax;

		if (g_syscall[count].ret != 5 && ret_val < 0)
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
}

void print_summary(double time)
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