#ifndef STRATUM_V2_TASK_H
#define STRATUM_V2_TASK_H

#include "global_state.h"

void stratum_v2_task(void *pvParameters);
void stratum_v2_close_connection(GlobalState *GLOBAL_STATE);
int stratum_v2_submit_share(GlobalState *GLOBAL_STATE, uint32_t job_id, uint32_t nonce,
                            uint32_t ntime, uint32_t version);

#endif // STRATUM_V2_TASK_H
