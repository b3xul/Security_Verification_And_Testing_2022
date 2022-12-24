//gcc bof3.c -o bof3 -fno-stack-protector 

#include <stdio.h>
#include <stdlib.h>

int main(){
char s[10];
int x=0;

gets(s);
if(x==0xcafecafe)
	printf("You won!\n");
else
	printf("Nope");
return 0;
}

