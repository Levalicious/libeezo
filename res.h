/*
 * res.h - resource aborts (2026-09-14).
 *
 * Allocation failure is never a typing judgement and never a reason to
 * continue: every path that cannot allocate reports 'resource limit: ...'
 * on stderr and exits 70, so callers and test harnesses can tell reaching
 * the machine's memory budget apart from a rejected program (Decision_
 * ResourceAbortStandard_Toolchain_2026_09_14).
 */
#ifndef EEZO_RES_H
#define EEZO_RES_H

#include <stddef.h>

void resource_die(const char *fmt, ...);
void *rmalloc(size_t n);
void *rcalloc(size_t n, size_t m);
void *rrealloc(void *p, size_t n);

#endif
