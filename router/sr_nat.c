
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */
	fprintf(stderr, "[DEBUG sr_nat_init] is called\n");
  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));
    /*
    time_t curtime = time(NULL);
		*/
    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

struct sr_nat_connection* copy_sr_nat_connection_linked_list(struct sr_nat_connection* src) {
	struct sr_nat_connection *head = NULL, *tail = NULL;
 	struct sr_nat_connection *walker = src;
	while(src != NULL) {
		struct sr_nat_connection* copy = calloc(1, sizeof(struct sr_nat_connection));
		memcpy(copy, walker, sizeof(struct sr_nat_connection));
		if(head == NULL) {
			head = copy;
			tail = copy;
		}else {
			tail->next = copy;
		}
		walker = walker->next;
	}
	return head;
}
/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  /* find mapping */
  struct sr_nat_mapping* walker = nat->mappings;
  while(walker != NULL) {
  	if(walker->ip_int == ip_int && walker->aux_int == aux_int && walker->type == type) {
  		break;
  	}
  	walker = walker->next;
  }

  struct sr_nat_mapping *copy = NULL;
  if(walker != NULL) {
  	copy = calloc(1, sizeof(struct sr_nat_mapping));
  	memcpy(copy, walker, sizeof(struct sr_nat_mapping));

  	/* Copy linked list connection */
  	copy->conns = copy_sr_nat_connection_linked_list(walker->conns);
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}


/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *copy = NULL;

  /* check ip_int and aux_int has already exist in NAT or not */
  struct sr_nat_mapping* walker = nat->mappings;
  while(walker != NULL) {
  	if(walker->ip_int == ip_int && walker->aux_int == aux_int) {
  		break;
  	}
  	walker = walker->next;
  }

  if(walker == NULL) {
  	/* create a new mapping and insert to NAT table */
  	struct sr_nat_mapping* new_mapping = calloc(1, sizeof(struct sr_nat_mapping));
  	new_mapping->type = type;
  	new_mapping->ip_int = ip_int;
  	new_mapping->aux_int = aux_int;

  	new_mapping->next = nat->mappings;
  	nat->mappings = new_mapping;

  	copy = calloc(1, sizeof(struct sr_nat_mapping));
  	memcpy(copy, new_mapping, sizeof(struct sr_nat_mapping));
  }
  
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
