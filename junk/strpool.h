/*
 * strpool.h - Minimal String Interning Library
 * A header-only C11 string interning library for efficient string storage and comparison
 *
 * Usage:
 *   const char *str1 = strpool_intern("hello");
 *   const char *str2 = strpool_intern("hello");
 *   assert(str1 == str2); // true, same pointer
 *
 *   // Or use the helper function:
 *   if (strpool_eq(str1, str2)) {
 *       // Strings are identical (pointer comparison)
 *   }
 */

#ifndef STRPOOL_H
#define STRPOOL_H

#include <assert.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../include/applespi/detail/cwisstable.h"

// Configuration macros (can be redefined before including this header)
#ifndef STRPOOL_INITIAL_CAPACITY
#define STRPOOL_INITIAL_CAPACITY 64
#endif

#ifndef STRPOOL_LOAD_FACTOR
#define STRPOOL_LOAD_FACTOR 0.75f
#endif

// Structure definitions
typedef struct strpool_entry {
    char *str;                  // Owned string copy
    uint32_t hash;              // Precomputed hash
    struct strpool_entry *next; // Next entry in bucket (for collisions)
} strpool_entry_t;

typedef struct {
    strpool_entry_t **buckets; // Hash table buckets
    size_t capacity;           // Number of buckets
    size_t count;              // Number of stored strings
} strpool_t;

#pragma mark cwisstables begin

static inline void kConsedCstrPolicy_copy(void *dst, const void *src) {
    printf("copy: dst: %p src: %p dst: 'n/a' src: '%s'\n", dst, src, (char *)src);
    assert(src);
    assert(dst);
    const char *src_cstr = (const char *)src;
    const size_t bytesz  = strlen(src_cstr) + 1;
    char *dst_cstr       = malloc(bytesz);
    assert(dst_cstr);
    memcpy(dst_cstr, src_cstr, bytesz);
    *(char **)dst = dst_cstr;
    printf("copy end: dst: %p src: %p dst: '%s' src: '%s'\n", dst, src, (char *)dst, (char *)src);
}

static inline void kConsedCstrPolicy_dtor(void *val) {
    printf("dtor: val: %p val: '%s'\n", val, (char *)val);
    assert(val);
    free(val);
}

static inline size_t kConsedCstrPolicy_hash(const void *val) {
    printf("hash: val: %p val: '%s'\n", val, (char *)val);
    const char *cstr         = (const char *)val;
    CWISS_FxHash_State state = 0;
    const size_t len         = strlen(cstr);
    CWISS_FxHash_Write(&state, &len, sizeof(len));
    CWISS_FxHash_Write(&state, cstr, len);
    return state;
}

static inline bool kConsedCstrPolicy_eq(const void *a, const void *b) {
    printf("eq: a: %p b: %p a: '%s' b: '%s'\n", a, b, (char *)a, (char *)b);
    return a == b;
}

CWISS_DECLARE_FLAT_SET_POLICY(kConsedCstrPolicy, char *, (obj_copy, kConsedCstrPolicy_copy),
                              (obj_dtor, kConsedCstrPolicy_dtor),
                              (key_hash, kConsedCstrPolicy_hash), (key_eq, kConsedCstrPolicy_eq));

CWISS_DECLARE_HASHSET_WITH(ConsedCstrSet, const char *, kConsedCstrPolicy);

#pragma mark cwisstables end

// Global string pool instance
static strpool_t _strpool = {0};

// FNV-1a hash function
static inline uint32_t _strpool_hash(const char *str) {
    uint32_t hash = 2166136261u; // FNV offset basis

    for (const char *p = str; *p; p++) {
        hash ^= (uint8_t)*p;
        hash *= 16777619u; // FNV prime
    }

    return hash;
}

// Initialize the string pool
static inline void _strpool_init(void) {
    if (_strpool.buckets == NULL) {
        _strpool.buckets = calloc(STRPOOL_INITIAL_CAPACITY, sizeof(strpool_entry_t *));
        if (!_strpool.buckets)
            abort(); // Out of memory
        _strpool.capacity = STRPOOL_INITIAL_CAPACITY;
        _strpool.count    = 0;
    }
}

// Resize the hash table
static void _strpool_resize(void) {
    size_t new_capacity           = _strpool.capacity * 2;
    strpool_entry_t **new_buckets = calloc(new_capacity, sizeof(strpool_entry_t *));
    if (!new_buckets)
        return; // If resize fails, continue with current table

    // Rehash all entries
    for (size_t i = 0; i < _strpool.capacity; i++) {
        strpool_entry_t *entry = _strpool.buckets[i];
        while (entry) {
            strpool_entry_t *next  = entry->next;
            size_t new_index       = entry->hash % new_capacity;
            entry->next            = new_buckets[new_index];
            new_buckets[new_index] = entry;
            entry                  = next;
        }
    }

    free(_strpool.buckets);
    _strpool.buckets  = new_buckets;
    _strpool.capacity = new_capacity;
}

/**
 * Intern a string
 *
 * Returns a unique pointer for each distinct string content. If the same
 * string content is interned multiple times, the same pointer is returned.
 * The returned pointer remains valid for the lifetime of the program.
 *
 * @param str The string to intern (will be copied)
 * @return Pointer to the interned string, or NULL if str was NULL
 */
const char *strpool_intern(const char *str) {
    if (!str)
        return NULL;

    // Initialize pool if needed
    if (!_strpool.buckets) {
        _strpool_init();
    }

    // Calculate hash and bucket index
    uint32_t hash = _strpool_hash(str);
    size_t index  = hash % _strpool.capacity;

    // Check if string already exists in pool
    for (strpool_entry_t *entry = _strpool.buckets[index]; entry; entry = entry->next) {
        if (entry->hash == hash && strcmp(entry->str, str) == 0) {
            return entry->str;
        }
    }

    // String not found, add it
    size_t len    = strlen(str);
    char *new_str = malloc(len + 1);
    if (!new_str)
        return NULL; // Out of memory

    memcpy(new_str, str, len + 1);

    strpool_entry_t *entry = malloc(sizeof(strpool_entry_t));
    if (!entry) {
        free(new_str);
        return NULL; // Out of memory
    }

    entry->str              = new_str;
    entry->hash             = hash;
    entry->next             = _strpool.buckets[index];
    _strpool.buckets[index] = entry;

    // Resize if load factor exceeded
    if (++_strpool.count > (size_t)(_strpool.capacity * STRPOOL_LOAD_FACTOR)) {
        _strpool_resize();
    }

    return new_str;
}

/**
 * Check if two interned strings are equal
 *
 * This is a simple pointer comparison, which is much faster than strcmp.
 * Only use this with strings that have been interned using strpool_intern().
 *
 * @param a First string to compare
 * @param b Second string to compare
 * @return true if the strings are identical, false otherwise
 */
static inline bool strpool_eq(const char *a, const char *b) {
    return a == b;
}

/**
 * Get the number of unique strings in the pool
 *
 * @return Number of unique strings stored
 */
static inline size_t strpool_count(void) {
    return _strpool.count;
}

#endif // STRPOOL_H
