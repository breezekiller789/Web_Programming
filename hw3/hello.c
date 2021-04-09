#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#define MaxLine 1024

int main(int argc, char *argv[]){

    int array[] = {1, 2, 3, 5, 6, 11};
    int n=0;
    char line[100];
    for(int i=0; i<6; i++){
        n += sprintf(&line[n], "%d", array[i]);
    }
    printf("%s\n", line);

    return 0;
}
