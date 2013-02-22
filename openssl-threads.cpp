/*
 * Copyright 2012 Andrew Ayer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 * 
 * Except as contained in this notice, the name(s) of the above copyright
 * holders shall not be used in advertising or otherwise to promote the
 * sale, use or other dealings in this Software without prior written
 * authorization.
 */

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

