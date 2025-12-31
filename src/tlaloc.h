#ifndef TLALOC_H
#define TLALOC_H

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

/*
Since man is mortal, the only immortality possible for him is to leave something behind him that is immortal since it will always move. 
This is the artist's way of scribbling "Kilroy was here" on the wall of the final and irrevocable oblivion through which he must someday pass.
~ William Faulkner ~
*/

/*
 * Incompatible with non-GCC/Clang toolchains. 
 * 
 * The __typeof__ keyword captures the type and evaluates once to prevent side effects contorting 
 * results.
 */

#define ALIGN_UP(x, align) ({           \
    __typeof__(x) _x = (x);             \
    __typeof__(align) _a = (align);     \
    (_x + _a - 1) & ~(_a - 1);          \
})

#define ALIGN_DOWN(x, align) ({         \
    __typeof__(x) _x = (x);             \
    __typeof__(align) _a = (align);     \
    _x & ~(_a - 1);                     \
})

/* Now cached. __builtin_expect() to hint the branch predictor.*/
static inline size_t tlaloc_page_size(void) {
    static size_t _cached = 0;
    if (__builtin_expect(_cached == 0, 0))
        _cached = (size_t)sysconf(_SC_PAGESIZE);
    if (_cached <= 0)
         _cached = 4096L;  
    return _cached;
}

#define PAGE_SIZE                 tlaloc_page_size()
#define PAGE_ALIGN(x)             ALIGN_UP((x), PAGE_SIZE)
#define PAGE_ALIGN_DOWN(x)        ALIGN_DOWN((x), PAGE_SIZE)

#define MIN(a, b) ({               \
    __typeof__(a) _a = (a);        \
    __typeof__(b) _b = (b);        \
    _a < _b ? _a : _b;             \
})

#define MAX(a, b) ({               \
    __typeof__(a) _a = (a);        \
    __typeof__(b) _b = (b);        \
    _a > _b ? _a : _b;             \
})

enum {
    DA_OK = 0,
    DA_NOMEM,
};

typedef struct {
    void  **items;
    size_t  count;
    size_t  capacity;
} dyn_array_t;

#define DA_APPEND(xs, x, r)                                                       \
    do {                                                                          \
        (r) = DA_OK;                                                              \
        if ((xs)->count >= (xs)->capacity) {                                      \
            size_t _cap = (xs)->capacity ? (xs)->capacity * 2 : 256;              \
            void *_tmp = realloc((xs)->items, _cap * sizeof *(xs)->items);        \
            if (!_tmp) { (r) = DA_NOMEM; break; }                                 \
            (xs)->items = _tmp;                                                   \
            (xs)->capacity = _cap;                                                \
        }                                                                         \
        (xs)->items[(xs)->count++] = (x);                                         \
    } while (0)

#define DA_FREE(xs)                                                               \
    do {                                                                          \
        free((xs)->items);                                                        \
        (xs)->items    = NULL;                                                    \
        (xs)->count    = 0;                                                       \
        (xs)->capacity = 0;                                                       \
    } while (0)

#endif /* TLALOC_H */

