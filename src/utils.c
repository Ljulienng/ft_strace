#include "ft_strace.h"

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