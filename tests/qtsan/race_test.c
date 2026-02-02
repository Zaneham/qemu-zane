/*
 * Simple data race test for QTSan
 * Two threads writing to the same variable without synchronization
 */
#include <pthread.h>
#include <stdio.h>

int shared_var = 0;

void *thread_func(void *arg)
{
    (void)arg;
    for (int i = 0; i < 1000; i++) {
        shared_var++;  /* DATA RACE HERE */
    }
    return NULL;
}

int main(void)
{
    pthread_t t1, t2;

    printf("Starting race test...\n");

    pthread_create(&t1, NULL, thread_func, NULL);
    pthread_create(&t2, NULL, thread_func, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("Final value: %d (expected 2000 if no race)\n", shared_var);
    return 0;
}
