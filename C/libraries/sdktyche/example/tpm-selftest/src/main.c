#define _GNU_SOURCE
#include "common.h"
#include "common_log.h"
#include "backend.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include "tyche_driver.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#define TPM_SELFTEST_BUFFER_SIZE 2048

// —————————————————————————————————— Main —————————————————————————————————— //

int main(int argc, char *argv[]) {
  char buff[TPM_SELFTEST_BUFFER_SIZE];
  tpm_selftest_buffer_t buff_info;

  // Open Tyche driver
  int tyche = open(DOMAIN_DRIVER, O_RDWR);
  if (tyche < 0) {
    ERROR("Could not open Tyche driver");
    goto failure;
  }

  // Prepare arguments and call into Tyche
  buff_info.result = 0;
  buff_info.start = (unsigned long)&buff[0];
  buff_info.size = TPM_SELFTEST_BUFFER_SIZE;
  buff_info.written = 0;
  if(ioctl(tyche, TYCHE_TPM_INFO, &buff_info) != SUCCESS) {
    ERROR("Tyche driver returned and error while serializing the attestation");
    goto failure;
  }

  LOG("TPM Self-Test Result: %lld\n", buff_info.result);

  if ((buff_info.result == 0) && (buff_info.written > 0)) {
    LOG("TPM MFTR: %s\n", buff);
  } else {
    ERROR("TPM MFTR could not be fetched.");
    goto failure;
  }


  return SUCCESS;
failure:
  return FAILURE;
}
