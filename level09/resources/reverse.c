#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
	int i = 0;
	int ascii = 0;
	char str[100] = {0};

	int fd = open("token", O_RDONLY);
	read(fd, str, 99);

	while (str[i]) {
		str[i] = str[i] - ascii;
		i++;
		ascii++;
	}

	printf("%s\n", str);
}