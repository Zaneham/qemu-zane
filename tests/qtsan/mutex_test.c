/*
 * Mutex test for QTSan - should NOT report races
 * Two threads accessing shared variable WITH synchronization
 */
#include <pthread.h>
#include <stdio.h>

int shared_var = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *thread_func(void *arg)
{
    int i;
    (void)arg;

    for (i = 0; i < 1000; i++) {
        pthread_mutex_lock(&mutex);
        shared_var++;
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}

int main(void)
{
    pthread_t t1, t2;

    printf("Starting mutex test (should have NO races)...\n");

    pthread_create(&t1, NULL, thread_func, NULL);
    pthread_create(&t2, NULL, thread_func, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("Final value: %d (expected 2000)\n", shared_var);
    return 0;
}
