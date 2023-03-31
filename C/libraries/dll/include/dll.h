#ifndef __INCLUDE_DLL_H__
#define __INCLUDE_DLL_H__

#define dll_elem(tpe, name) \
  struct {                  \
    tpe* prev;              \
    tpe* next;              \
  } name;

#define dll_list(tpe, name) \
  struct {                  \
    tpe* head;              \
    tpe* tail;              \
  } name;

#define dll_init_list(list) \
  (list)->head = 0;         \
  (list)->tail = 0;

#define dll_init_elem(elem, name) \
  do {                            \
    (elem)->name.prev = 0;        \
    (elem)->name.next = 0;        \
  } while (0);

#define dll_is_empty(list) \
  ((list)->head == 0 && (list)->tail == 0)

#define dll_foreach(list, curr, name) \
  for (curr = (list)->head; (curr) != 0; (curr) = (curr)->name.next)

#define dll_add(list, elem, name)       \
  do {                                  \
    if ((list)->head == 0) {            \
      (list)->head = (elem);            \
      (list)->tail = (elem);            \
    } else {                            \
      (list)->tail->name.next = (elem); \
      (elem)->name.prev = (list)->tail; \
      (list)->tail = (elem);            \
    }                                   \
  } while (0);

#define dll_add_after(list, elem, name, previous) \
  do {                                            \
    (elem)->name.next = (previous)->name.next;    \
    (elem)->name.prev = (previous);               \
    (previous)->name.next = (elem);               \
    if ((elem)->name.next != 0) {                 \
      (elem)->name.next->name.prev = (elem);      \
    }                                             \
    if ((list)->tail == (previous)) {             \
      (list)->tail = elem;                        \
    }                                             \
  } while (0);

#define dll_add_first(list, elem, name) \
  do {                                  \
    (elem)->name.prev = 0;              \
    (elem)->name.next = (list)->head;   \
    if ((list)->head != 0) {            \
      (list)->head->name.prev = (elem); \
    }                                   \
    (list)->head = (elem);              \
    if ((list)->tail == 0) {            \
      (list)->tail = (elem);            \
    }                                   \
  } while (0);

#define dll_remove(list, elem, name)                    \
  do {                                                  \
    if ((elem)->name.prev != 0) {                       \
      (elem)->name.prev->name.next = (elem)->name.next; \
    }                                                   \
    if ((elem)->name.next != 0) {                       \
      (elem)->name.next->name.prev = (elem)->name.prev; \
    }                                                   \
    if ((list)->head == (elem)) {                       \
      (list)->head = (elem)->name.next;                 \
    }                                                   \
    if ((list)->tail == (elem)) {                       \
      (list)->tail = (elem)->name.prev;                 \
    }                                                   \
    (elem)->name.next = 0;                              \
    (elem)->name.prev = 0;                              \
  } while (0);

#define dll_contains(start, end, val) ((start <= val) && (val < end))

#define dll_overlap(s1, e1, s2, e2) ((((s1 <= s2) && (s2 < e1)) || ((s2 <= s1) && (s1 < e2))))

#endif
