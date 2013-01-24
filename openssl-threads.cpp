#include "openssl-threads.hpp"
#include <pthread.h>
#include <openssl/crypto.h>

static pthread_mutex_t* mutexes = NULL;
 
static void locking_callback (int mode, int n, const char* file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&mutexes[n]);
	else
		pthread_mutex_unlock(&mutexes[n]);
}
 
static unsigned long id_callback ()
{
	return pthread_self();
}
 
void openssl_init_threads ()
{
	if (!mutexes) {
		mutexes = new pthread_mutex_t[CRYPTO_num_locks()];
		for (int i = 0; i < CRYPTO_num_locks(); ++i) {
			pthread_mutex_init(&mutexes[i], NULL);
		}
		CRYPTO_set_id_callback(id_callback);
		CRYPTO_set_locking_callback(locking_callback);
	}
}

void openssl_cleanup_threads ()
{
	if (mutexes) {
		CRYPTO_set_id_callback(NULL);
		CRYPTO_set_locking_callback(NULL);
		for (int i = 0; i < CRYPTO_num_locks(); ++i) {
			pthread_mutex_destroy(&mutexes[i]);
		}
		delete[] mutexes;
		mutexes = NULL;
	}
}

