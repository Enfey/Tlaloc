#ifndef TLALOC_H
#define TLALOC_H

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#define ALIGN_UP(x, align)      (((x) + (align) - 1) & ~((align) - 1))
#define ALIGN_DOWN(x, align)    ((x) & ~((align) - 1))

#define PAGE_SIZE               ((size_t)sysconf(_SC_PAGESIZE))
#define PAGE_ALIGN(x)           ALIGN_UP((x), PAGE_SIZE)
#define PAGE_ALIGN_DOWN(x)      ALIGN_DOWN((x), PAGE_SIZE)

#define MIN(a, b)               (((a) < (b)) ? (a) : (b))
#define MAX(a, b)               (((a) > (b)) ? (a) : (b))

enum {
    DA_OK = 0,
    DA_NOMEM,
};

typedef struct {
    void  **items;
    size_t  count;
    size_t  capacity;
} dyn_array_t;

#define DA_APPEND(xs, x, r)                                                    \
    do {                                                                       \
        (r) = DA_OK;                                                           \
        if ((xs)->count >= (xs)->capacity) {                                   \
            size_t _cap = (xs)->capacity ? (xs)->capacity * 2 : 256;           \
            void *_tmp = realloc((xs)->items, _cap * sizeof *(xs)->items);     \
            if (!_tmp) { (r) = DA_NOMEM; break; }                              \
            (xs)->items = _tmp;                                                \
            (xs)->capacity = _cap;                                             \
        }                                                                      \
        (xs)->items[(xs)->count++] = (x);                                      \
    } while (0)

#define DA_FREE(xs)                                                            \
    do {                                                                       \
        free((xs)->items);                                                     \
        (xs)->items    = NULL;                                                 \
        (xs)->count    = 0;                                                    \
        (xs)->capacity = 0;                                                    \
    } while (0)

#endif /* TLALOC_H */

