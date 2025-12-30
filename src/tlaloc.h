#include <stdlib.h>

enum {
    DA_OK = 0,
    DA_NOMEM,
};

typedef struct {
    void **items;   /*generic pointer container for now, will expand the array types as necessary.*/
    size_t count;
    size_t capacity;
} dyn_array_t;

#define da_append(xs, x)                                                        \
    do {                                                                        \
        if ((xs)->count >= (xs)->capacity) {                                    \
            if ((xs)->capacity == 0) (xs)->capacity = 256;                      \
            else (xs)->capacity *= 2;                                           \
            void *tmp;                                                          \
            _r = DA_OK;                                                         \
            tmp = realloc((xs)->items, (xs)->capacity * sizeof *(xs)->items);   \
            if (!tmp && (xs)->capacity) {da_free(xs); _r = DA_NOMEM;}           \
            if(_r == DA_OK) (xs)->items = tmp;                                  \
            _r;                                                                 \
        }                                                                       \
        (xs)->items[(xs)->count++] = (x);                                       \
    } while (0)

#define da_free(xs)                     \
    do {                                \
        free((xs)->items);              \
        (xs)->items = NULL;             \
        (xs)->count = 0;                \
        (xs)->capacity = 0;             \
    } while (0)

