#include <stdlib.h>
#include <stdio.h>

#define ARRAY_SIZE 10000000
#define STRIDE 64

int main() {
    int *array = malloc(sizeof(int) * ARRAY_SIZE);
    if (!array) {
        perror("malloc failed");
        return 1;
    }

    for (size_t i = 0; i < ARRAY_SIZE; i += STRIDE) {
        array[i] = i;
    }

    printf("Accessing large array to generate cache misses...\n");
    for (size_t i = 0; i < ARRAY_SIZE; i += STRIDE) {
        array[i] *= 2; // Access non-contiguous memory locations
    }

    free(array);
    return 0;
}
