#include <stdlib.h>
#include "dll.h"
#include "common.h"

typedef struct elem_t {
  int value;

  dll_elem(struct elem_t, list);
} elem_t;

typedef struct list_t {
  dll_list(elem_t, get); 
} list_t;

static void add_remove(list_t* l)
{
  size_t size = 6;
  int values [6] = {1,2,3,4,5,6};
  for (int i = 0; i < 6; i++) {
    elem_t* elem = malloc(sizeof(elem_t)); 
    TEST(elem != NULL);
    elem->value = values[i];
    dll_init_elem(elem, list);
    dll_add(&(l->get), elem, list);
  }

  // Test non-destructiveness of dll_foreach.
  for (int rep = 0; rep < 5; rep++) {
    int i = 0;
    elem_t* curr = NULL;
    dll_foreach(&(l->get), curr, list) {
      TEST(curr->value == values[i]);
      i++;
    } 
    TEST(i == size);
  }

  // Test remove head;
  elem_t* first = l->get.head;
  TEST(first->value == 1);
  dll_remove(&(l->get), first, list);
  TEST(first->value == 1);
  TEST(first->list.prev == NULL);
  TEST(first->list.next == NULL);
  // Check the order;
  do {
    int i = 1;
    elem_t* curr = NULL;
    dll_foreach(&(l->get), curr, list) {
      TEST(curr->value == values[i]);
      i++;
    }
    TEST(i == size);
  } while(0);
  dll_add_first(&(l->get), first, list);

  // Remove the one before last.
  elem_t* five = l->get.tail->list.prev;
  TEST(five->value == 5);
  dll_remove(&(l->get), five, list);
  TEST(five->list.prev == NULL);
  TEST(five->list.next == NULL);
  do {
    int i = 0;
    elem_t* curr;
    dll_foreach(&(l->get), curr, list) {
      TEST(curr->value == values[i]);
      i++;
      if (i == 4) {
        i++;
      }
    }
    TEST(i == size);
  } while(0);
}


// Reproduce the shitty case.

typedef enum region_type_t {
  TYPE1 = 0,
  TYPE2 = 1,
} region_type_t;


typedef struct region_t {
  unsigned long start;
  unsigned long end;

  region_type_t tpe;
  
  dll_elem(struct region_t, globals);
} region_t;

static int overlap(unsigned long s1, unsigned long e1, unsigned long s2, unsigned long e2)
{
  if ((s1 <= s2) && (s2 < e1)) {
    goto fail;
  }

  if ((s2 <= s1) && (s1 < e2)) {
    goto fail;
  }
  return 0;
fail:
  return 1;
}

typedef struct enclave_t {
  dll_list(region_t, all_pages);
} enclave_t;

static void dump_region(region_t* reg)
{
  printf("[%lx]: %lx - %lx | %d | %lx, %lx\n",reg, reg->start, reg->end, reg->tpe, reg->globals.prev, reg->globals.next);
}

static void debug_info(enclave_t* enclave, region_t* to_add)
{
  if (to_add != NULL) {
    printf("to_add: ");
    dump_region(to_add);
  }
  region_t* iter;
  printf("The list: [%lx] -- [%lx]\n", enclave->all_pages.head, enclave->all_pages.tail);
  dll_foreach(&(enclave->all_pages), iter, globals) {
    dump_region(iter);
  }
}

int add_merge_global(enclave_t* enclave, region_t* region)
{
  region_t* iter = NULL;
  region_t* prev = NULL;
  if (enclave == NULL || region == NULL) {
    return -1;
  }
  for(iter = enclave->all_pages.head; iter != NULL;) {
    if (overlap(iter->start, iter->end, region->start, region->end)) {
      TEST(0);
    }

    // CASES WHERE: region is on the left.

    // Too far in the list already and no merge.
    if (iter->start > region->end
        || (iter->start == region->end && iter->tpe != region->tpe)) {
      break;
    }

    // Contiguous, we merge on if the types are the same.
    if (iter->start == region->end && iter->tpe == region->tpe) {
      iter->start = region->start;
      free(region);
      region = NULL;
      prev = NULL;
      break;
    }

    // CASES WHERE: region is on the right.
    
    // Safely skip this entry.
    if (iter->end < region->start
        || (iter->end == region->start && iter->tpe != region->tpe)) {
      goto next;
    }

    // We need to merge and have no guarantee the next region does not 
    // overlap.
    if (iter->end == region->start && iter->tpe == region->tpe) {
      region_t* next = iter->globals.next;
      // There is an overlap with the next element.
      // We cannot add the region to the list.
      if (next != NULL && overlap(iter->start, region->end, next->start, next->end)) {
        TEST(0);
        goto failure;
      }
      // Merge and remove.
      region->start = iter->start;
      dll_remove(&(enclave->all_pages), iter, globals);
      free(iter);
      iter = prev;
      if (prev != NULL) {
        prev = prev->globals.prev;
      } else {
        prev = NULL;
        iter = enclave->all_pages.head;
      }
      continue;
    }
next:
    prev = iter;
    iter = iter->globals.next;
  }
  // The region has been merge on the left.
  if (region == NULL) {
    printf("Goto done");
    goto done; 
  }

  if (prev != NULL) {
    dll_add_after(&(enclave->all_pages), region, globals, prev);
  } else {
    dll_add_first(&(enclave->all_pages), region, globals);
  }
done:
  return 0;
failure:
  return -1;
}

#define max 11

static void enclave_bug() {
  unsigned long starts[max] = {
    0x104ab9000,
    0x10799d000,
    0x107925000,
    0x109545000,
    0x10953e000,
    0x1095b5000,
    0x109536000,
    0x10953d000,
    0x1095b2000,
    0x1095b4000,
    0x1095b6000,
  };
  unsigned long ends[max] = {
    0x104aba000,
    0x10799e000,
    0x107926000,
    0x109546000,
    0x10953f000,
    0x1095b6000,
    0x109537000,
    0x10953e000,
    0x1095b3000,
    0x1095b5000,
    0x1095b7000,
  }; 

  region_type_t types [max] = {
    0,
    0,
    0,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
  };
  region_t* regions[max];
  for (int i = 0; i < max; i++) {
    regions[i] = malloc(sizeof(region_t));
    TEST(regions[i] != NULL);
    regions[i]->start = starts[i];
    regions[i]->end = ends[i];
    regions[i]->tpe = types[i];
    dll_init_elem(regions[i], globals);
  }

  enclave_t enclave;
  dll_init_list(&(enclave.all_pages));
  for (int i = 0; i < max; i++) {
    printf("Iteration: %d\n", i);
    debug_info(&enclave, regions[i]);
    add_merge_global(&enclave, regions[i]);
    printf("\n");
  }
  printf("The final list\n");
  debug_info(&enclave, NULL);
}

void enclave_bug_minimal()
{
  unsigned long starts [] = {
    0x1000,
    0x2000,
    0x5000,
    0x7000,
    0x8000,
  };

  unsigned long ends [] = {
    0x2000,
    0x3000,
    0x6000,
    0x8000,
    0x9000,
  };

  region_type_t types [] = {
    0, 
    1, 
    1,
    1,
    1,
  };
  region_t* regions[5];
  for (int i = 0; i < 5; i++) {
    regions[i] = malloc(sizeof(region_t));
    TEST(regions[i] != NULL);
    regions[i]->start = starts[i];
    regions[i]->end = ends[i];
    regions[i]->tpe = types[i];
    dll_init_elem(regions[i], globals);
  }
  enclave_t enclave;
  dll_init_list(&(enclave.all_pages));
  for (int i = 0; i < 5; i++) {
    printf("Iteration %d:\n", i);
    debug_info(&enclave, regions[i]);
    add_merge_global(&enclave, regions[i]);
    printf("\n");
  }

  printf("Final list:\n");
  debug_info(&enclave, NULL);
}

int main(void) {
  list_t l; 
  dll_init_list(&(l.get));
  add_remove(&l);
  enclave_bug();
  //enclave_bug_minimal();
}
