#include "ubench.h"
#include "measurement.h"
#include "common.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include "tyche_api.h"
#include "ecs.h"
#include "tyche_driver.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define WIDTH (80)
#define COL_WIDTH (25)

// ———————————————————————————— Static functions ———————————————————————————— //

///TODO: make this more generic I guess.
static void print_line(const char* col1, const char* col2, const char* col3) {
	int pad = 0;
	assert(col1 != NULL);
	if (col1 != NULL) {
		printf("%s", col1);
		pad = COL_WIDTH - strlen(col1);
	} else {
		pad = COL_WIDTH;
	}
	for (int i = 0; i < pad; i++) {
		putchar(' ');
	}
	if (col2 != NULL) {
		printf("%s", col2);
		pad = COL_WIDTH - strlen(col2);
	} else {
		pad = COL_WIDTH;
	}
	for (int i = 0; i < pad; i++) {
		putchar(' ');
	}
	if (col3 != NULL) {
		printf("%s", col3);
		pad = COL_WIDTH - strlen(col3);
	} else {
		pad = COL_WIDTH;
	}
	for (int i = 0; i < pad; i++) {
		putchar(' ');
	}
	printf("\n");
}

static bool run_create_delete_iterations(
		char* name,
		size_t offset,
		ubench_config_t* bench,
		time_diff_t* create_res,
		time_diff_t* delete_res,
		size_t res_size) {
	assert(name != NULL && bench != NULL);
	time_measurement_t start;
	time_measurement_t end;

	tyche_domain_t* domains = calloc(bench->nb_iterations, sizeof(tyche_domain_t));
	assert(domains != NULL);

	assert(take_time(&start));
	for (int i = 0; i < bench->nb_iterations; i++) {
		assert(sdk_create_domain(&domains[i], name, 1, NO_TRAPS, DEFAULT_PERM) == SUCCESS);
	}
	assert(take_time(&end));
	assert(create_res != NULL);
	create_res[offset] = compute_elapsed(&start, &end);

	// Delete
	assert(take_time(&start));
	for (int i = 0; i < bench->nb_iterations; i++) {
		assert(sdk_delete_domain(&domains[i]) == SUCCESS);
	}
	assert(take_time(&end));
	delete_res[offset] = compute_elapsed(&start, &end);
	return true;
}

static bool bench_find_switch(capa_index_t* res) {
	capa_index_t next = 0;
	assert(res != NULL);
	do {
		capability_t tmp_capa;
		if (enumerate_capa(next, &next, &tmp_capa) != SUCCESS || next == 0) {
			goto failure;
		}
		/// We found it.
		if (tmp_capa.capa_type == Switch) {
			*res = tmp_capa.local_id;
			return true;
		}
	} while (next != 0);
failure:
	// Something went wrong.
	return false;
}

// ————————————————————————————— API functions —————————————————————————————— //

void display_create_delete(
		const char* prefix, 
		ubench_config_t *bench,
		time_diff_t* create_res,
		time_diff_t* delete_res) {
	assert(prefix != NULL && bench != NULL && create_res != NULL && delete_res != NULL);
	char buf2[COL_WIDTH] = {0};
	char buf3[COL_WIDTH] = {0};
	
	
	// Print the header.
	printf("Create/delete for %ld iterations\n", bench->nb_iterations);
	sprintf(buf2, "create (%s)", TIME_MEASUREMENT_UNIT);
	sprintf(buf3, "delete (%s)", TIME_MEASUREMENT_UNIT);
	print_line(prefix, buf2, buf3); 	

	// Print the lines
	for (domain_size_t i = bench->min; i <= bench->max; i++) {
		int idx = i - bench->min;
		sprintf(buf2, "%.3f", create_res[idx]);
		sprintf(buf3, "%.3f", delete_res[idx]);
		print_line(domain_size_names[i], buf2, buf3);
	}
	printf("\n");
}

bool run_create_delete(
		const char* prefix,
		ubench_config_t* bench,
		time_diff_t* create_res,
		time_diff_t* delete_res,
		size_t res_size) {
	assert(prefix != NULL && bench != NULL && res_size > 0);
	
	for (int i = bench->min; i <= bench->max; i++) {
		char name[100] = {0};
		size_t offset = i - bench->min;
		sprintf(name, "%s/%s", prefix, domain_size_names[i]);
		assert(run_create_delete_iterations(name, offset, bench, create_res, delete_res, res_size));
	}
	return true;
}

bool run_transition(
		const char* prefix,
		ubench_config_t *bench,
		time_diff_t* results,
		time_diff_t* raws) {
	tyche_domain_t domain;
	char name[100] = {0};
	capa_index_t capa_switch = 0;
	usize core_mask = sdk_pin_to_current_core();
	assert(prefix != NULL && bench != NULL && results != NULL && raws != NULL);
	sprintf(name, "%s/transition", prefix);
	assert(sdk_create_domain(&domain, name, core_mask, ALL_TRAPS, DEFAULT_PERM) == SUCCESS);
	// Warmup transition.
	assert(sdk_call_domain(&domain) == SUCCESS);
	// Let's go for the sdk benchmark.
	for (int i = 0; i < bench->rep_iter; i++) {
		time_measurement_t start;
		time_measurement_t end;
		assert(take_time(&start));
		for (int j = 0; j < bench->nb_iterations; j++) {
			assert(sdk_call_domain(&domain) == SUCCESS);
		}
		assert(take_time(&end));
		results[i] = compute_elapsed(&start, &end);
	}

#ifdef RUN_WITH_KVM
  printf("RAW SEEMS UNSTABLE WITH KVM\n. DISABLED\n");
#else
	// Now perform the raws benchmark.
	// First find the transition handle.
	assert(bench_find_switch(&capa_switch));
	for (int i = 0; i < bench->rep_iter; i++) {
		time_measurement_t start;
		time_measurement_t end;
		assert(take_time(&start));
		for (int j = 0; j < bench->nb_iterations; j++) {
			// A raw syscall.
			asm volatile(
					"movq %0, %%rdi\n\t"
					"movq %1, %%rax\n\t"
					"vmcall\n\t"
					:
					: "rm" (capa_switch), "rm" ((usize)TYCHE_SWITCH)
					: "rax", "rdi", "memory");
		}
		assert(take_time(&end));
		raws[i] = compute_elapsed(&start, &end);
	}
#endif
	// Clean up the domain.
	assert(sdk_delete_domain(&domain) == SUCCESS);
	return true;
}

void display_transition(
		const char* prefix,
		ubench_config_t* bench,
		time_diff_t *results,
		time_diff_t *raws) {
	assert(prefix != NULL && results != NULL && raws != NULL);
	// Print the header.
	printf("Transition %s: Repeated %ld times %ld calls\n", prefix, bench->rep_iter, bench->nb_iterations);
	char buf1[COL_WIDTH] = {0};
	char buf2[COL_WIDTH] = {0};
	char buf3[COL_WIDTH] = {0};
	sprintf(buf1, "%ld sdkcalls/rawcalls (%s)", bench->nb_iterations, TIME_MEASUREMENT_UNIT);
	sprintf(buf2, "per sdk-transition (%s)", TIME_MEASUREMENT_UNIT);
	sprintf(buf3, "per raw-transition (%s)", TIME_MEASUREMENT_UNIT);
	print_line(buf1, buf2, buf3);
	
	for (int i = 0; i < bench->rep_iter; i++) {
		double estimate = (results[i]) / (2.0 * ((double)bench->nb_iterations));
		double estimate2 = (raws[i]) / (2.0 * ((double)bench->nb_iterations));
		sprintf(buf1, "%.3f/%.3f", results[i], raws[i]);
		sprintf(buf2, "%.3f", estimate);
#ifdef RUN_WITH_KVM
    sprintf(buf3, "NA");
#else
		sprintf(buf3, "%.3f", estimate2);
#endif
		print_line(buf1, buf2, buf3);
	}
	printf("\n");
}

/// Buffer used in the attestation.
/// Not that it makes a massive difference, but let's align it.
static char attestation_buffer[4096] __attribute__((aligned(4096))) = {0};

bool run_attestation(
		const char* prefix,
		ubench_config_t* bench,
		time_diff_t* results,
		usize *sizes) {
	assert(prefix != NULL && bench != NULL && results != NULL && sizes != NULL);
	attest_buffer_t buff_info;
	// Load the domains first.
#ifdef RUN_WITH_KVM
	fprintf(stderr, "YOU ARE RUNNING ATTESTION WITH KVM\nRegions are not transfered yet!\n");
	return false;
#endif
	size_t nb_domains = bench->max - bench->min + 1;
	tyche_domain_t* domains = calloc(nb_domains, sizeof(tyche_domain_t));
	assert(domains != NULL);
	for (domain_size_t i = bench->min; i <= bench->max; i++) {
		char name[100] = {0};
		sprintf(name, "%s/%s", prefix, domain_size_names[i]);
		int idx = i - bench->min;
		assert(sdk_create_domain(&domains[idx], name, 1, NO_TRAPS, DEFAULT_PERM) == SUCCESS);
	}

	// Initialize the request buffer.
	buff_info.start = (unsigned long) &attestation_buffer[0];
	buff_info.size = 4096;
	buff_info.written = 0;

	// Now run the benchmark.
	for (int i = 0; i < bench->rep_iter; i++) {
		time_measurement_t start;
		time_measurement_t end;
		assert(take_time(&start));
		for (int j = 0; j < bench->nb_iterations; j++) {
			assert(ioctl(domains[0].handle, TYCHE_GET_ATTESTATION, &buff_info) == SUCCESS);
			assert(buff_info.written > 0);
		}
		assert(take_time(&end));
		results[i] = compute_elapsed(&start, &end);
		sizes[i] = buff_info.written;
	}

	// Cleanup the domains.
	for (domain_size_t i = bench->min; i <= bench->max; i++) {
		int idx = i - bench->min;
		assert(sdk_delete_domain(&domains[idx]) == SUCCESS);
	}
	return true;
}

void display_attestation(
		const char* prefix,
		ubench_config_t* bench,
		time_diff_t* results,
		usize *sizes) {
	char buf1[100] = {0};
	char buf2[100] = {0};
	char buf3[100] = {0};
	assert(prefix != NULL && results != NULL && sizes != NULL);
	// Print the header.
	printf("Attestation: rep(%ld), nb_iter(%ld)\n", bench->rep_iter, bench->nb_iterations);
	printf("%s/{ ", prefix);
	for (int i = bench->min; i <= bench->max; i++) {
		printf("%s ", domain_size_names[i]);
	}
	putchar('\n');
	sprintf(buf1, "%ld calls (%s)", bench->nb_iterations, TIME_MEASUREMENT_UNIT);
	sprintf(buf2, "avg (%s)/call", TIME_MEASUREMENT_UNIT);
	sprintf(buf3, "#bytes/call");
	print_line(buf1, buf2, buf3);
	for (int i = 0; i < bench->rep_iter; i++) {
		sprintf(buf1, "%.3f", results[i]);
		sprintf(buf2, "%.3f", results[i] / ((double) bench->nb_iterations));
		sprintf(buf3, "%lld", sizes[i]);
		print_line(buf1, buf2, buf3);
	}
	printf("\n");
}
