/*
 * res.c - resource aborts (see res.h)
 */
#include "res.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

void resource_die(const char *fmt, ...) {
    va_list ap;
    fflush(stdout);
    fputs("resource limit: ", stderr);
    va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
    exit(70);
}

void *rmalloc(size_t n) { void *p = malloc(n ? n : 1); if (!p) resource_die("out of memory (%zu bytes)", n); return p; }
void *rcalloc(size_t n, size_t m) { void *p = calloc(n ? n : 1, m ? m : 1); if (!p) resource_die("out of memory (%zu x %zu bytes)", n, m); return p; }
void *rrealloc(void *p, size_t n) { void *q = realloc(p, n ? n : 1); if (!q) resource_die("out of memory (%zu bytes)", n); return q; }
