#ifndef __INCLUDE_MY_SHARED_H__
#define __INCLUDE_MY_SHARED_H__

typedef struct my_encl_message_t {
  void* message;
  unsigned int message_len;
  char reply[30];
} my_encl_message_t;

#endif
