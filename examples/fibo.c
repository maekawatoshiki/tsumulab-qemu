#include <stdio.h>
#define print(x) printf(#x " = %d\n", x)

int fibo(int x) {
    if (x <= 2) return 1;
    return fibo(x - 1) + fibo(x - 2);
}

int main() {
    print(fibo(30));
    return 0;
}

