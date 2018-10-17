/* Copyright (c) 2017 The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "core/or/or.h"
#include "core/or/circuitpadding.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/relay.h"
#include "feature/stats/rephist.h"

#include "core/or/channel.h"

#include "lib/time/compat_time.h"
#include "lib/crypt_ops/crypto_rand.h"

#include "core/or/crypt_path_st.h"
#include "core/or/circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "feature/nodelist/routerstatus_st.h"
#include "feature/nodelist/node_st.h"
#include "core/or/cell_st.h"
#include "core/or/extend_info_st.h"
#include "core/crypto/relay_crypto.h"
#include "feature/nodelist/nodelist.h"

HANDLE_IMPL(circpad_machineinfo, circpad_machineinfo_t,);
#define circpad_machineinfo_handle_free(h)    \
   FREE_AND_NULL(circpad_machineinfo_handle_t, \
                 circpad_machineinfo_handle_free_, (h))

#define USEC_PER_SEC (1000000)

void circpad_machine_remove_token(circpad_machineinfo_t *mi);
void circpad_send_padding_cell_for_callback(circpad_machineinfo_t *mi);
circpad_decision_t circpad_machine_schedule_padding(circpad_machineinfo_t *mi);
circpad_decision_t circpad_machine_transition(circpad_machineinfo_t *mi,
                                              circpad_transition_t event);
circpad_machineinfo_t *circpad_circuit_machineinfo_new(circuit_t *on_circ,
                                               int machine_index);
STATIC uint32_t circpad_histogram_bin_to_usec(circpad_machineinfo_t *mi,
                                              int bin);
STATIC int circpad_histogram_usec_to_bin(circpad_machineinfo_t *mi,
                                              uint32_t us);

STATIC const circpad_state_t *circpad_machine_current_state(
                                      circpad_machineinfo_t *machine);
void circpad_machine_remove_lower_token(circpad_machineinfo_t *mi,
                                        uint64_t target_bin_us);
void circpad_machine_remove_higher_token(circpad_machineinfo_t *mi,
                                        uint64_t target_bin_us);
void circpad_machine_remove_closest_token(circpad_machineinfo_t *mi,
                                          uint64_t target_bin_us,
                                          int use_usec);
STATIC void circpad_machine_setup_tokens(circpad_machineinfo_t *mi);
static inline circpad_purpose_mask_t circpad_circ_purpose_to_mask(uint8_t
                                          circ_purpose);
static inline circpad_circuit_state_t circpad_circuit_state(
                                        origin_circuit_t *circ);
static void circpad_circuit_machineinfo_free_idx(circuit_t *circ, int idx);
static void circpad_setup_machine_on_circ(circuit_t *on_circ,
                                          circpad_machine_t *machine);

/* Machines for various usecases */
static smartlist_t *origin_padding_machines = NULL;
static smartlist_t *relay_padding_machines = NULL;

/**
 * Return the circpad_stat_t for the current state based on the
 * mutable info.
 */
STATIC const circpad_state_t *
circpad_machine_current_state(circpad_machineinfo_t *machine)
{
  switch (machine->current_state) {
    case CIRCPAD_STATE_START:
    case CIRCPAD_STATE_END:
      return NULL;

    case CIRCPAD_STATE_BURST:
      return &CIRCPAD_GET_MACHINE(machine)->burst;

    case CIRCPAD_STATE_GAP:
      return &CIRCPAD_GET_MACHINE(machine)->gap;
  }

  log_fn(LOG_WARN,LD_CIRC,
         "Invalid circuit padding state %d",
         machine->current_state);
  //tor_fragile_assert();

  return NULL;
}

/**
 * Calculate the lower bound of a histogram bin. The upper bound
 * is obtained by calling this function with bin+1, and subtracting 1.
 */
STATIC uint32_t
circpad_histogram_bin_to_usec(circpad_machineinfo_t *mi, int bin)
{
  const circpad_state_t *state = circpad_machine_current_state(mi);
  uint32_t start_usec;

  if (state->use_rtt_estimate)
    start_usec = mi->rtt_estimate+state->start_usec;
  else
    start_usec = state->start_usec;

  if (bin == 0)
    return start_usec;

  return start_usec
      + (state->range_sec*USEC_PER_SEC)/(1<<(state->histogram_len-bin));
}

/**
 * Calculate the bin that contains the usec argument.
 * "Contains" is defined as us in [lower, upper).
 */
STATIC int
circpad_histogram_usec_to_bin(circpad_machineinfo_t *mi, uint32_t us)
{
  const circpad_state_t *state = circpad_machine_current_state(mi);
  uint32_t start_usec;
  int bin;

  if (state->use_rtt_estimate)
    start_usec = mi->rtt_estimate+state->start_usec;
  else
    start_usec = state->start_usec;

  if (us <= start_usec)
    return 0;

  bin = state->histogram_len -
    tor_log2((state->range_sec*USEC_PER_SEC)/(us-start_usec+1))-1;

  /* Clamp the return value to account for timevals before the start
   * of bin 0, or after the last bin */
  if (bin >= state->histogram_len || bin < 0) {
    bin = MIN(MAX(bin, 0), state->histogram_len-1);
  }
  return bin;
}

/**
 * This function frees any token bins allocated from a previous state
 *
 * Called after a state transition, or if the bins are empty.
 */
STATIC void
circpad_machine_setup_tokens(circpad_machineinfo_t *mi)
{
  const circpad_state_t *state = circpad_machine_current_state(mi);

  /* If this state doesn't exist, or doesn't have token removal,
   * free any previous state's histogram, and bail */
  if (!state || state->token_removal == CIRCPAD_TOKEN_REMOVAL_NONE) {
    if (mi->histogram) {
      tor_free(mi->histogram);
      mi->histogram = NULL;
      mi->histogram_len = 0;
    }
    return;
  }

  /* Try to avoid re-mallocing if we don't really need to */
  if (!mi->histogram || (mi->histogram
          && mi->histogram_len != state->histogram_len)) {
    tor_free(mi->histogram); // null ok
    mi->histogram = tor_malloc_zero(sizeof(uint16_t)*state->histogram_len);
  }
  mi->histogram_len = state->histogram_len;

  memcpy(mi->histogram, state->histogram,
         sizeof(uint16_t)*state->histogram_len);
}

/**
 * Sample an expected time-until-next-packet delay from the histogram.
 *
 * The bin is chosen with probability proportional to the number
 * of tokens in each bin, and then a time value is chosen uniformly from
 * that bin's [start,end) time range.
 */
static uint32_t
circpad_machine_sample_delay(circpad_machineinfo_t *mi)
{
  const circpad_state_t *state = circpad_machine_current_state(mi);
  const uint16_t *histogram = NULL;
  int i = 0;
  uint32_t curr_weight = 0;
  uint32_t histogram_total = 0;
  uint32_t bin_choice;
  uint32_t bin_start, bin_end;

  tor_assert(state);

  if (state->token_removal != CIRCPAD_TOKEN_REMOVAL_NONE) {
    tor_assert(mi->histogram && mi->histogram_len == state->histogram_len);

    histogram = mi->histogram;
    for (int b = 0; b < state->histogram_len; b++)
      histogram_total += histogram[b];
  } else {
    histogram = state->histogram;
    histogram_total = state->histogram_total;
  }

  bin_choice = crypto_rand_int(histogram_total);

  /* Skip all the initial zero bins */
  while (!histogram[i]) {
    i++;
  }
  curr_weight = histogram[i];

  // TODO: This is not constant-time. Pretty sure we don't
  // really need it to be, though.
  while (curr_weight < bin_choice) {
    i++;
    tor_assert(i < state->histogram_len);
    curr_weight += histogram[i];
  }

  tor_assert(i < state->histogram_len);
  tor_assert(histogram[i] > 0);

  // Store this index to remove the token upon callback.
  if (state->token_removal != CIRCPAD_TOKEN_REMOVAL_NONE) {
    mi->chosen_bin = i;
  }

  /* XXX-circpad_event: Should we even decrement the infinity bin? */
  if (i == state->histogram_len-1) {
    fprintf(stderr, "Infinity pad!\n");
    if (state->token_removal != CIRCPAD_TOKEN_REMOVAL_NONE) {
      tor_assert(mi->histogram[i] > 0);
      mi->histogram[i]--;
    }

    // Infinity: Don't send a padding packet. Wait for a real packet
    // and then see if our bins are empty or what else we should do.
    return CIRCPAD_DELAY_INFINITE;
  }

  tor_assert(i < state->histogram_len - 1);

  bin_start = circpad_histogram_bin_to_usec(mi, i);
  bin_end = circpad_histogram_bin_to_usec(mi, i+1);

  // Sample uniformly between histogram[i] to histogram[i+1]-1
  return bin_start + crypto_rand_int(bin_end - bin_start);
}

/**
 * Find the index of the first bin whose upper bound is
 * greater than the target, and that has tokens remaining.
 *
 * XXX: Why uint64_t here but uint32_t elsewhere? We should
 * stick to one. Do we really need 64 bits? Maybe..
 */
static int
circpad_machine_first_higher_index(circpad_machineinfo_t *mi,
                                   uint64_t target_bin_us)
{
  int i = circpad_histogram_usec_to_bin(mi, target_bin_us);

  if (i < 0)
    return mi->histogram_len;

  /* Don't remove from the infinity bin */
  for (; i < mi->histogram_len-1; i++) {
    if (mi->histogram[i] &&
        circpad_histogram_bin_to_usec(mi, i+1) > target_bin_us) {
      return i;
    }
  }

  return mi->histogram_len;
}

/**
 * Find the index of the first bin whose lower bound is
 * lower than the target, and that has tokens remaining.
 */
static int
circpad_machine_first_lower_index(circpad_machineinfo_t *mi,
                                  uint64_t target_bin_us)
{
  int i = circpad_histogram_usec_to_bin(mi, target_bin_us);

  /* Don't remove from the infinity bin */
  if (i >= mi->histogram_len-1) {
    i = mi->histogram_len-2;
  }

  for (; i >= 0; i--) {
    if (mi->histogram[i] &&
        circpad_histogram_bin_to_usec(mi, i) <= target_bin_us) {
      return i;
    }
  }

  return -1;
}

/**
 * Remove a token from the first non-empty bin whose upper bound is
 * greater than the target.
 */
void
circpad_machine_remove_higher_token(circpad_machineinfo_t *mi,
                                    uint64_t target_bin_us)
{
  /* We need to remove the token from the first bin
   * whose upper bound is greater than the target, and that
   * has tokens remaining. */
  int i = circpad_machine_first_higher_index(mi, target_bin_us);

  if (i == mi->histogram_len) {
    fprintf(stderr, "No more upper tokens: %p\n", mi);
  } else {
    tor_assert(mi->histogram[i]);
    mi->histogram[i]--;
  }
}

/**
 * Remove a token from the first non-empty bin whose upper bound is
 * lower than the target.
 */
void
circpad_machine_remove_lower_token(circpad_machineinfo_t *mi,
                                   uint64_t target_bin_us)
{
  /* First, check if we came before bin 0. In which case, decrement it. */
  if (mi->histogram[0] &&
      circpad_histogram_bin_to_usec(mi, 0) > target_bin_us) {
    mi->histogram[0]--;
    fprintf(stderr, "Token removal: %p %d\n", mi, mi->histogram[0]);
  } else {
    /* Otherwise, we need to remove the token from the first bin
     * whose upper bound is lower than the target, and that
     * has tokens remaining. */
    int i = circpad_machine_first_lower_index(mi, target_bin_us);

    if (i == -1) {
      fprintf(stderr, "No more lower tokens: %p\n", mi);
    } else {
      tor_assert(mi->histogram[i]);
      mi->histogram[i]--;
    }
  }
}

/**
 * Remove a token from the closest non-empty bin to the target.
 *
 * If use_usec is true, measure "closest" in terms of bin start usec.
 * If it is false, use bin index distance only.
 */
void
circpad_machine_remove_closest_token(circpad_machineinfo_t *mi,
                                     uint64_t target_bin_us,
                                     int use_usec)
{
  /* First, check if we came before bin 0. In which case, decrement it. */
  if (mi->histogram[0] &&
      circpad_histogram_bin_to_usec(mi, 0) > target_bin_us) {
    mi->histogram[0]--;
    fprintf(stderr, "Token removal: %p %d\n", mi, mi->histogram[0]);
  } else {
    int lower = circpad_machine_first_lower_index(mi, target_bin_us);
    int higher = circpad_machine_first_higher_index(mi, target_bin_us);
    int current = circpad_histogram_usec_to_bin(mi, target_bin_us);
    uint64_t lower_us;
    uint64_t higher_us;

    tor_assert(lower <= current);
    tor_assert(higher >= current);

    if (higher == mi->histogram_len && lower == -1) {
      // Bins are empty
      return;
    } else if (higher == mi->histogram_len) {
      // Higher bins are empty
      tor_assert(mi->histogram[lower]);
      mi->histogram[lower]--;
      return;
    } else if (lower == -1) {
      // Lower bins are empty
      tor_assert(mi->histogram[higher]);
      mi->histogram[higher]--;
      return;
    }

    if (use_usec) {
      lower_us = (circpad_histogram_bin_to_usec(mi, lower) +
                  circpad_histogram_bin_to_usec(mi, lower+1))/2;
      higher_us = (circpad_histogram_bin_to_usec(mi, higher) +
                  circpad_histogram_bin_to_usec(mi, higher+1))/2;

      if (target_bin_us < lower_us) {
        // Lower bin is closer
        tor_assert(mi->histogram[lower]);
        mi->histogram[lower]--;
        return;
      } else if (target_bin_us > higher_us) {
        // Higher bin is closer
        tor_assert(mi->histogram[higher]);
        mi->histogram[higher]--;
        return;
      } else if (target_bin_us - lower_us > higher_us - target_bin_us) {
        // Higher bin is closer
        tor_assert(mi->histogram[higher]);
        mi->histogram[higher]--;
        return;
      } else {
        // Lower bin is closer
        tor_assert(mi->histogram[lower]);
        mi->histogram[lower]--;
        return;
      }
    } else {
      if (current - lower > higher - current) {
        // Higher bin is closer
        tor_assert(mi->histogram[higher]);
        mi->histogram[higher]--;
        return;
      } else {
        // Lower bin is closer
        tor_assert(mi->histogram[lower]);
        mi->histogram[lower]--;
        return;
      }
    }
  }
}

/**
 * Remove a token from the bin corresponding to the delta since
 * last packet. If that bin is empty, choose a token based on
 * the specified removal strategy in the state machine. */
void
circpad_machine_remove_token(circpad_machineinfo_t *mi)
{
  const circpad_state_t *state = circpad_machine_current_state(mi);
  uint64_t current_time = monotime_absolute_usec();
  uint64_t target_bin_us;
  uint32_t histogram_total = 0;

  /* Dont remove any tokens if there was no padding scheduled */
  if (!mi->padding_scheduled_at_us) {
    return;
  }

  /* If we have scheduled padding some time in the future, we want to see what
     bin we are in at the current time */
  target_bin_us = current_time - mi->padding_scheduled_at_us;

  /* We are treating this non-padding cell as a padding cell, so we cancel
     padding timer, if present. */
  mi->padding_scheduled_at_us = 0;
  if (mi->padding_timer_scheduled) {
    mi->padding_timer_scheduled = 0;
    timer_disable(mi->padding_timer);
  }

  /* If we are not in a padding state (like start or end) or if we are not
   * removing tokens we dont need to do any of that */
  if (!state || state->token_removal == CIRCPAD_TOKEN_REMOVAL_NONE)
    return;

  tor_assert(mi->histogram && mi->histogram_len == state->histogram_len);

  /* Perform the specified token removal strategy */
  switch (state->token_removal) {
    case CIRCPAD_TOKEN_REMOVAL_NONE:
      return;
    case CIRCPAD_TOKEN_REMOVAL_CLOSEST_USEC:
      circpad_machine_remove_closest_token(mi, target_bin_us, 1);
    case CIRCPAD_TOKEN_REMOVAL_CLOSEST:
      circpad_machine_remove_closest_token(mi, target_bin_us, 0);
    case CIRCPAD_TOKEN_REMOVAL_LOWER:
      circpad_machine_remove_lower_token(mi, target_bin_us);
      break;
    case CIRCPAD_TOKEN_REMOVAL_HIGHER:
      circpad_machine_remove_higher_token(mi, target_bin_us);
      break;
  }

  /* Check if bins empty. This requires summing up the current mutable
   * machineinfo histogram token total and checking if it is zero.
   * Machineinfo does not keep a running token count. We're assuming the
   * extra space is not worth this short loop iteration.
   *
   * We also do not count infinity bin in histogram totals. */
  for (int b = 0; b < state->histogram_len-1; b++)
    histogram_total += mi->histogram[b];

  if (histogram_total == 0) {
    circpad_event_bins_empty(mi);
  }
}

/**
 * Send a relay command with a relay cell payload on a circuit to
 * the particular hopnum.
 *
 * Hopnum starts at 1 (1=guard, 2=middle, 3=exit, etc).
 *
 * Payload may be null.
 *
 * Returns negative on error, 0 on success.
 */
static int
circpad_send_command_to_hop(origin_circuit_t *circ, int hopnum,
                            uint8_t relay_command, const uint8_t *payload,
                            ssize_t payload_len)
{
  crypt_path_t *target_hop = circuit_get_cpath_hop(circ, hopnum);
  int ret;

  /* Check that the cpath has the target hop */
  if (!target_hop) {
    log_fn(LOG_WARN,LD_CIRC,
           "Padding circuit %u has %d hops, not %d",
           circ->global_identifier,
           circuit_get_cpath_len(circ), hopnum);
    return -1;
  }

  /* Check that enough hops are opened.
   * XXX: I think we can just check the target_hop state
   * directly and it's equivalent? */
  if (circuit_get_cpath_opened_len(circ) < hopnum) {
    log_fn(LOG_WARN,LD_CIRC,
           "Padding circuit %u has %d hops, not %d",
           circ->global_identifier,
           circuit_get_cpath_opened_len(circ), hopnum);
    return -1;
  }

  log_fn(LOG_INFO,LD_CIRC, "Negotiating padding on circuit %u.",
          circ->global_identifier);

  /* Send the drop command to the second hop */
  ret = relay_send_command_from_edge(0, TO_CIRCUIT(circ), relay_command,
                                     (const char*)payload, payload_len,
                                     target_hop);
  return ret;
}

/**
 * Callback helper to send a padding cell.
 *
 * This helper is called after our histogram-sampled delay period passes
 * without another packet being sent first. If a packet is sent before this
 * callback happens, it is canceled. So when we're called here, send padding
 * right away.
 */
void
circpad_send_padding_cell_for_callback(circpad_machineinfo_t *mi)
{
  mi->padding_scheduled_at_us = 0;

  // Make sure circuit didn't close on us
  if (mi->on_circ->marked_for_close) {
    log_fn(LOG_INFO,LD_CIRC,
           "Padding callback on a circuit marked for close. Ignoring.");
    return;
  }

  if (mi->histogram && mi->histogram_len) {
    tor_assert(mi->chosen_bin < mi->histogram_len);
    tor_assert(mi->histogram[mi->chosen_bin] > 0);
    mi->histogram[mi->chosen_bin]--;
  }

  log_fn(LOG_INFO,LD_CIRC, "Padding callback. Sending.");

  if (CIRCUIT_IS_ORIGIN(mi->on_circ)) {
    circpad_send_command_to_hop(TO_ORIGIN_CIRCUIT(mi->on_circ),
                                CIRCPAD_GET_MACHINE(mi)->target_hopnum,
                                RELAY_COMMAND_DROP, NULL, 0);
  } else {
    // If we're a non-origin circ, we can just send from here as if we're the
    // edge.
    relay_send_command_from_edge(0, mi->on_circ, RELAY_COMMAND_DROP, NULL,
                                 0, NULL);
  }

  /* Check if bins empty. Right now, we're operating under the assumption
   * that this loop is better than the extra space for maintaining a
   * running total in machineinfo. Also note that the above
   * relay_send could cause a transition, but this is OK because
   * that will refill tokens anyway. */
  if (mi->histogram && mi->histogram_len) {
    uint32_t histogram_total = 0;

    /* We do not count the infinity bin for bins empty event */
    for (int b = 0; b < mi->histogram_len-1; b++)
      histogram_total += mi->histogram[b];

    if (histogram_total == 0) {
      circpad_event_bins_empty(mi);
    }
  }
}

/**
 * Tor-timer compatible callback that tells us to send a padding cell.
 *
 * Conver the handle to a pointer; do some basic sanity checks, then
 * send appropriate data to the callback helper to send the cell.
 */
static void
circpad_send_padding_callback(tor_timer_t *timer, void *args,
                              const struct monotime_t *time)
{
  circpad_machineinfo_t *mi =
    circpad_machineinfo_handle_get((struct circpad_machineinfo_handle_t*)args);
  (void)timer; (void)time;

  if (mi && mi->on_circ) {
    assert_circuit_ok(mi->on_circ);
    circpad_send_padding_cell_for_callback(mi);
  } else {
    // This shouldn't happen (represents a handle leak)
    log_fn(LOG_WARN,LD_CIRC,
            "Circuit closed while waiting for padding timer.");
    tor_fragile_assert();
  }

  // TODO-MP-AP: Unify this counter with channelpadding for rephist stats
  //total_timers_pending--;
}

/**
 * Schedule the next padding time according to the machineinfo on a
 * circuit.
 *
 * The histograms represent inter-packet-delay. Whenever you get an packet
 * event you should be scheduling your next timer (after cancelling any old
 * ones and updating tokens accordingly).
 */
circpad_decision_t
circpad_machine_schedule_padding(circpad_machineinfo_t *mi)
{
  uint32_t in_us = 0;
  struct timeval timeout;
  tor_assert(mi);

  log_fn(LOG_INFO, LD_CIRC, "Scheduling padding?");
  // Don't pad in either state start or end (but
  // also don't cancel any previously scheduled padding
  // either).
  if (mi->current_state == CIRCPAD_STATE_START ||
      mi->current_state == CIRCPAD_STATE_END) {
    log_fn(LOG_INFO, LD_CIRC, "Padding end state");
    return CIRCPAD_NONPADDING_STATE;
  }

  if (mi->padding_timer_scheduled) {
    /* Cancel current timer (if any) */
    timer_disable(mi->padding_timer);
    mi->padding_timer_scheduled = 0;
  }

  /* in_us = in microseconds */
  in_us = circpad_machine_sample_delay(mi);

  log_fn(LOG_INFO,LD_CIRC,"Padding in %u usec\n", in_us);

  if (in_us <= 0) {
    mi->padding_scheduled_at_us = monotime_absolute_usec();
    circpad_send_padding_cell_for_callback(mi);
    return CIRCPAD_PADDING_SENT;
  }

  // Don't schedule if we have infinite delay.
  if (in_us == CIRCPAD_DELAY_INFINITE) {
    // XXX-circpad_event: Return differently if we transition or not?
    // XXX: Don't count infinity bin for bins empty? Do we still
    // decrement tokens?
    circpad_event_infinity(mi);
    return CIRCPAD_WONTPAD_INFINITY;
  }

  timeout.tv_sec = in_us/USEC_PER_SEC;
  timeout.tv_usec = (in_us%USEC_PER_SEC);

  log_fn(LOG_INFO, LD_CIRC, "Padding in %u sec, %u usec\n",
          (unsigned)timeout.tv_sec, (unsigned)timeout.tv_usec);

  if (!mi->on_circ->padding_handles[mi->machine_index]) {
    mi->on_circ->padding_handles[mi->machine_index] =
        circpad_machineinfo_handle_new(mi);
  }

  if (mi->padding_timer) {
    timer_set_cb(mi->padding_timer,
                 circpad_send_padding_callback,
                 mi->on_circ->padding_handles[mi->machine_index]);
  } else {
    mi->padding_timer =
        timer_new(circpad_send_padding_callback,
                  mi->on_circ->padding_handles[mi->machine_index]);
  }
  timer_schedule(mi->padding_timer, &timeout);
  mi->padding_timer_scheduled = 1;
  mi->padding_scheduled_at_us = monotime_absolute_usec();

  // TODO-MP-AP: Unify with channelpadding counter
  //rep_hist_padding_count_timers(++total_timers_pending);

  return CIRCPAD_PADDING_SCHEDULED;
}

/**
 * Generic state transition function for padding state machines.
 *
 * Given an event and our mutable machine info, decide if/how to
 * transition to a different state, and perform actions accordingly.
 */
circpad_decision_t
circpad_machine_transition(circpad_machineinfo_t *mi,
                           circpad_transition_t event)
{
  const circpad_state_t *state =
      circpad_machine_current_state(mi);

  /* XXX can we make the start state transition also generic? Can we
   * give them a dummy circpad_state_t to combine with the burst+gap
   * blocks below? */

  /* Check start state transitions */
  if (!state) {
    /* If state is null we are in start state or end state.
       If we in end state we don't pad no matter what. */
    if (mi->current_state == CIRCPAD_STATE_START) {
      /* If we are in start state, first check the burst transition events to
         see if we should transition to burst */
      if (CIRCPAD_GET_MACHINE(mi)->transition_burst_events & event) {
        mi->current_state = CIRCPAD_STATE_BURST;
        circpad_machine_setup_tokens(mi);
        return circpad_machine_schedule_padding(mi);
      }
      if (CIRCPAD_GET_MACHINE(mi)->transition_gap_events & event) {
        mi->current_state = CIRCPAD_STATE_GAP;
        circpad_machine_setup_tokens(mi);
        return circpad_machine_schedule_padding(mi);
      }
    }

    return CIRCPAD_WONTPAD_EVENT;
  }

  /* Check cancel events and cancel any pending padding */
  if (state->transition_cancel_events & event) {
    mi->padding_scheduled_at_us = 0;
    if (mi->padding_timer_scheduled) {
      mi->padding_timer_scheduled = 0;
      /* Cancel current timer (if any) */
      timer_disable(mi->padding_timer);
      return CIRCPAD_WONTPAD_CANCELED;
    }
    return CIRCPAD_WONTPAD_EVENT;
  }

  /* See if we need to transition to any other states based on this event.
   * Whenever a transition happens, even to our own state, we schedule padding.
   *
   * So if a state only wants to schedule padding for an event, it specifies a
   * transition to itself. All non-specified events are ignored.
   */
  for (circpad_statenum_t s = CIRCPAD_STATE_START; s < CIRCPAD_NUM_STATES;
       s++) {
    if (state->transition_events[s] & event) {
      /* If this is not the same state, switch and init tokens,
       * otherwise just reschedule padding. */
      if (mi->current_state != s) {
        mi->current_state = s;
        circpad_machine_setup_tokens(mi);
      }

      return circpad_machine_schedule_padding(mi);
    }
  }

  return CIRCPAD_WONTPAD_EVENT;
}

/**
 * Estimate the circuit RTT from the current middle hop out to the
 * end of the circuit.
 *
 * We estimate RTT by calculating the time between "receive" and
 * "send" at a middle hop. This is because we "receive" a cell
 * from the origin, and then relay it towards the exit before a
 * response comes back. It is that response time from the exit side
 * that we want to measure, so that we can make use of it for synthetic
 * response delays.
 */
static void
circpad_estimate_circ_rtt_on_received(circuit_t *circ,
                                      circpad_machineinfo_t *mi)
{
  /* Origin circuits don't estimate RTT. They could do it easily enough,
   * but they have no reason to use it in any delay calculations. */
  if (CIRCUIT_IS_ORIGIN(circ) || mi->stop_rtt_update)
    return;

  /* If we already have a last receieved packet time, that means we
   * did not get a response before this packet. The RTT estimate
   * only makes sense if we do not have multiple packets on the
   * wire, so stop estimating if this is the second packet
   * back to back. However, for the first set of back-to-back
   * packets, we can wait until the very first response comes back
   * to us, to measure that RTT (for the response to optimistic
   * data, for example). Hence stop_rtt_update is only checked
   * in this received side function, and not in send side below.
   */
  if (mi->last_received_time_us) {
    /* We also allow multiple back-to-back packets if the circuit is not
     * opened, to handle var cells */
    if (circ->state == CIRCUIT_STATE_OPEN) {
      log_fn(LOG_INFO, LD_CIRC,
           "Stopping padding RTT estimation on circuit (%"PRIu64
           ", %d) after two back to back packets. Current RTT: %d",
           circ->n_chan ?  circ->n_chan->global_identifier : 0,
           circ->n_circ_id, mi->rtt_estimate);
       mi->stop_rtt_update = 1;
    }
  } else {
    mi->last_received_time_us = monotime_absolute_usec();
  }
}

/**
 * Handles the "send" side of RTT calculation at middle nodes.
 *
 * This function calculates the RTT from the middle to the end
 * of the circuit by subtracting the last received cell timestamp
 * from the current time. It allows back-to-back cells until
 * the circuit is opened, to allow for var cell handshakes.
 */
static void
circpad_estimate_circ_rtt_on_send(circuit_t *circ,
                                  circpad_machineinfo_t *mi)
{
  /* Origin circuits don't estimate RTT. They could do it easily enough,
   * but they have no reason to use it in any delay calculations. */
  if (CIRCUIT_IS_ORIGIN(circ))
    return;

  /* If last_received_time_us is non-zero, we are waiting for a response
   * from the exit side. Calculate the time delta and use it as RTT. */
  if (mi->last_received_time_us) {
    uint64_t rtt_time = monotime_absolute_usec() -
        mi->last_received_time_us;

    /* Reset the last RTT packet time, so we can tell if two cells
     * arrive back to back */
    mi->last_received_time_us = 0;

    /* Use INT32_MAX to ensure the addition doesn't overflow */
    if (rtt_time >= INT32_MAX) {
      log_fn(LOG_WARN,LD_CIRC,
             "Circuit padding RTT estimate overflowed: %"PRIu64
             " vs %"PRIu64, monotime_absolute_usec(),
               mi->last_received_time_us);
      return;
    }

    /* If the circuit is opened and we have an RTT estimate, update
     * via an EWMA. */
    if (circ->state == CIRCUIT_STATE_OPEN && mi->rtt_estimate) {
      mi->rtt_estimate += (uint32_t)rtt_time;
      mi->rtt_estimate /= 2;
    } else {
      /* If the circuit is not opened yet, just replace the estimate */
      mi->rtt_estimate = (uint32_t)rtt_time;
    }
  } else if (circ->state == CIRCUIT_STATE_OPEN) {
    /* If last_received_time_us is zero, then we have gotten two cells back
     * to back. Stop estimating RTT in this case. Note that we only
     * stop RTT update if the circuit is opened, to allow for RTT estimates
     * of var cells during circ setup. */
    mi->stop_rtt_update = 1;

    if (!mi->rtt_estimate) {
      log_fn(LOG_NOTICE, LD_CIRC,
             "Got two cells back to back on a circuit before estimating RTT.");
    }
  }
}

/**
 * A "non-padding" cell has been sent from this endpoint. React
 * according to any padding state machines on the circuit.
 *
 * For origin circuits, this means we sent a cell into the network.
 * For middle relay circuits, this means we sent a cell towards the
 * origin.
 */
void
circpad_event_nonpadding_sent(circuit_t *on_circ)
{
  /* If there are no machines then this loop should not iterate */
  for (int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
       i++) {
    /* First, update any RTT estimate */
    circpad_estimate_circ_rtt_on_send(on_circ, on_circ->padding_info[i]);

    /* Remove a token: this is the idea of adaptive padding, since we have an
       ideal distribution that we want our distribution to look like */
    circpad_machine_remove_token(on_circ->padding_info[i]);

    circpad_machine_transition(on_circ->padding_info[i],
                               CIRCPAD_TRANSITION_ON_NONPADDING_SENT);
  }
}

/**
 * A "non-padding" cell has been received by this endpoint. React
 * according to any padding state machines on the circuit.
 *
 * For origin circuits, this means we read a cell from the network.
 * For middle relay circuits, this means we received a cell from the
 * origin.
 */
void
circpad_event_nonpadding_received(circuit_t *on_circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
      i++) {
    /* First, update any RTT estimate */
    circpad_estimate_circ_rtt_on_received(on_circ, on_circ->padding_info[i]);

    circpad_machine_transition(on_circ->padding_info[i],
                               CIRCPAD_TRANSITION_ON_NONPADDING_RECV);
  }
}

/**
 * A padding cell has been sent from this endpoint. React
 * according to any padding state machines on the circuit.
 *
 * For origin circuits, this means we sent a cell into the network.
 * For middle relay circuits, this means we sent a cell towards the
 * origin.
 */
void
circpad_event_padding_sent(circuit_t *on_circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
       i++) {
    circpad_machine_transition(on_circ->padding_info[i],
                             CIRCPAD_TRANSITION_ON_PADDING_SENT);
  }
}

/**
 * A padding cell has been received by this endpoint. React
 * according to any padding state machines on the circuit.
 *
 * For origin circuits, this means we read a cell from the network.
 * For middle relay circuits, this means we received a cell from the
 * origin.
 */
void
circpad_event_padding_received(circuit_t *on_circ)
{
  /* identical to padding sent */
  for (int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
       i++) {
    circpad_machine_transition(on_circ->padding_info[i],
                              CIRCPAD_TRANSITION_ON_PADDING_RECV);
  }
}

/**
 * An "infinite" delay has ben chosen from one of our histograms.
 *
 * "Infinite" delays mean don't send padding -- but they can also
 * mean transition to another state depending on the state machine
 * definitions. Check the rules and react accordingly.
 */
void
circpad_event_infinity(circpad_machineinfo_t *mi)
{
  circpad_machine_transition(mi, CIRCPAD_TRANSITION_ON_INFINITY);
}

/**
 * All of the bins of our current state's histogram's are empty.
 *
 * Check to see if this means transition to another state, and if
 * not, refill the tokens.
 */
void
circpad_event_bins_empty(circpad_machineinfo_t *mi)
{
  if (!circpad_machine_transition(mi, CIRCPAD_TRANSITION_ON_BINS_EMPTY)) {
    /* If we dont transition, then we refill the tokens */
    circpad_machine_setup_tokens(mi);
  }
}

/**
 * Returns true if the circuit matches the conditions.
 */
static inline int
circpad_machine_conditions_met(origin_circuit_t *circ,
                               const circpad_machine_t *machine)
{
  if (!(circpad_circ_purpose_to_mask(TO_CIRCUIT(circ)->purpose)
      & machine->conditions.purpose_mask))
    return 0;

  if (!(circpad_circuit_state(circ) & machine->conditions.state_mask))
    return 0;

  if (circuit_get_cpath_opened_len(circ) < machine->conditions.min_hops)
    return 0;

  return 1;
}

/**
 * Returns a minimized representation of the circuit state.
 *
 * The padding code only cares if the circuit is building,
 * opened, or used for streams. This returns which one is true.
 */
static inline
circpad_circuit_state_t
circpad_circuit_state(origin_circuit_t *circ)
{
  if (circ->p_streams)
    return CIRCPAD_CIRC_STREAMS;

  if (TO_CIRCUIT(circ)->state == CIRCUIT_STATE_OPEN)
    return CIRCPAD_CIRC_OPENED;

  return CIRCPAD_CIRC_BUILDING;
}

/**
 * Convert a normal circuit purpose into a bitmask that we can
 * use for determining matching circuits.
 */
static inline
circpad_purpose_mask_t
circpad_circ_purpose_to_mask(uint8_t circ_purpose)
{
  /* Treat OR circ purposes as ignored. They should not be passed here*/
  if (circ_purpose <= CIRCUIT_PURPOSE_OR_MAX_) {
    // XXX: BUG
    return 0;
  }

  /* Treat new client circuit purposes as "OMG ITS EVERYTHING".
   * This also should not happen */
  if (circ_purpose - CIRCUIT_PURPOSE_OR_MAX_ - 1 > 32) {
    // XXX: Bug
    return 255;
  }

  /* Convert the purpose to a bit position */
  return 1 << (circ_purpose - CIRCUIT_PURPOSE_OR_MAX_ - 1);
}

/**
 * Shut down any machines whose conditions no longer match
 * the current circuit.
 */
static void
circpad_shutdown_old_machines(origin_circuit_t *on_circ)
{
  circuit_t *circ = TO_CIRCUIT(on_circ);

  for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
    if (!circ->padding_machine[i])
      continue;

    if (!circpad_machine_conditions_met(on_circ,
                                        circ->padding_machine[i])) {
      // Clear machineinfo (frees timers)
      circpad_circuit_machineinfo_free_idx(circ, i);
      // Send padding negotiate stop
      circpad_negotiate_padding(on_circ,
                                circ->padding_machine[i]->machine_num,
                                circ->padding_machine[i]->target_hopnum,
                                CIRCPAD_COMMAND_STOP);
    }
  }
}

/**
 * Negotiate new machines that would apply to this circuit.
 */
static void
circpad_add_matching_machines(origin_circuit_t *on_circ)
{
  circuit_t *circ = TO_CIRCUIT(on_circ);

#ifdef TOR_UNIT_TESTS
  /* Tests don't have to init our padding machines */
  // XXX: Should we make them, so they exercise us?
  if (!origin_padding_machines)
    return;
#endif

  for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
    if (circ->padding_info[i])
      continue;

    /* We have a free index */
    SMARTLIST_FOREACH_REVERSE_BEGIN(origin_padding_machines,
                                    circpad_machine_t *,
                                    machine) {
      if (machine->machine_index == i &&
          circpad_machine_conditions_met(on_circ, machine)) {

        // We can only replace this machine if the target hopnum
        // is the same, otherwise we'll get invalid data
        if (circ->padding_machine[i]) {
          if (circ->padding_machine[i]->target_hopnum !=
              machine->target_hopnum)
            continue;
          /* Replace it. (Don't free - is global). */
          circ->padding_machine[i] = NULL;
        }

        circpad_negotiate_padding(on_circ, machine->machine_num,
                                  machine->target_hopnum,
                                  CIRCPAD_COMMAND_START);
        circpad_setup_machine_on_circ(circ, machine);
      }
    } SMARTLIST_FOREACH_END(machine);
  }
}

/**
 * Event that tells us we added a hop to an origin circuit.
 *
 * This event is used to decide if we should create a padding machine
 * on a circuit.
 */
void
circpad_machine_event_circ_added_hop(origin_circuit_t *on_circ)
{
  /* Since our padding conditions do not specify a max_hops,
   * all we can do is add machines here */
  circpad_add_matching_machines(on_circ);
}

/**
 * Event that tells us that an origin circuit is now built.
 *
 * Shut down any machines that only applied to un-built circuits.
 * Activate any new ones.
 */
void
circpad_machine_event_circ_built(origin_circuit_t *circ)
{
  circpad_shutdown_old_machines(circ);
  circpad_add_matching_machines(circ);
}

/**
 * Circpad purpose changed event.
 *
 * Shut down any machines that don't apply to our circ purpose.
 * Activate any new ones that do.
 */
void
circpad_machine_event_purpose_changed(origin_circuit_t *circ)
{
  circpad_shutdown_old_machines(circ);
  circpad_add_matching_machines(circ);
}

/**
 * Streams attached event.
 *
 * Called from link_apconn_to_circ() and handle_hs_exit_conn()
 *
 * Shut down any machines that only applied to machines without
 * streams. Activate any new ones.
 */
void
circpad_machine_event_circ_has_streams(origin_circuit_t *circ)
{
  circpad_shutdown_old_machines(circ);
  circpad_add_matching_machines(circ);
}

/**
 * Streams detached event.
 *
 * Called from circuit_detach_stream()
 *
 * Shut down any machines that only applied to machines without
 * streams. Activate any new ones.
 */
void
circpad_machine_event_circ_has_no_streams(origin_circuit_t *circ)
{
  circpad_shutdown_old_machines(circ);
  circpad_add_matching_machines(circ);
}

/**
 * Verify that padding is coming from the expected hop.
 *
 * Returns true if from_hop matches the target hop from
 * one of our padding machines.
 *
 * Returns false if we're not an origin circuit, or if from_hop
 * does not match one of the padding machines.
 */
int
circpad_padding_is_from_expected_hop(circuit_t *circ,
                                     crypt_path_t *from_hop)
{
  crypt_path_t *target_hop = NULL;
  if (!CIRCUIT_IS_ORIGIN(circ))
    return 0;

  for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
    if (!circ->padding_machine[i])
      continue;

    target_hop = circuit_get_cpath_hop(TO_ORIGIN_CIRCUIT(circ),
                    circ->padding_machine[i]->target_hopnum);

    if (target_hop == from_hop)
      return 1;
  }

  return 0;
}

/**
 * Deliver circpad events for an "unrecognized cell".
 *
 * Unrecognized cells are sent to relays and are forwarded
 * onto the next hop of their circuits. Unrecognized cells
 * are by definition not padding. We need to tell relay-side
 * state machines that a non-padding cell was sent or received,
 * depending on the direction, so they can update their histograms
 * and decide to pad or not.
 */
void
circpad_deliver_unrecognized_cell_events(circuit_t *circ,
                                         cell_direction_t dir)
{
  if (!CIRCUIT_IS_ORIGIN(circ)) {
    // XXX: Log? Bug? We should never see unrecognized
    // cells at origin.
    return;
  }

  if (dir == CELL_DIRECTION_OUT) {
    /* When direction is out (away from origin), then we received non-padding
       cell coming from the origin to us. */
    circpad_event_nonpadding_received(circ);
  } else if (dir == CELL_DIRECTION_IN) {
    /* It's in and not origin, so the cell is going away from us.
     * So we are relaying a non-padding cell towards the origin. */
    circpad_event_nonpadding_sent(circ);
  }
}

/**
 * Deliver circpad events for "recognized" relay cells.
 *
 * Recognized cells are destined for this hop, either client or middle.
 * Check if this is a padding cell or not, and send the appropiate
 * received event.
 */
void
circpad_deliver_recognized_relay_cell_events(circuit_t *circ,
                                             uint8_t relay_command,
                                             crypt_path_t *layer_hint)
{
  /* Padding negotiate cells are ignored by the state machines
   * for simplicity. */
  if (relay_command == RELAY_COMMAND_PADDING_NEGOTIATE ||
      relay_command == RELAY_COMMAND_PADDING_NEGOTIATED) {
    return;
  }

  if (relay_command == RELAY_COMMAND_DROP) {
    rep_hist_padding_count_read(PADDING_TYPE_DROP);

    if (CIRCUIT_IS_ORIGIN(circ)) {
      if (circpad_padding_is_from_expected_hop(circ, layer_hint)) {
        circuit_read_valid_data(TO_ORIGIN_CIRCUIT(circ), 0);
      } else {
        /* This is unexpected padding. Ignore it for now. */
        return;
      }
    }

    /* The cell should be recognized by now, which means that we are on the
       destination, which means that we received a padding cell. We might be
       the client or the Middle node, still, because leaky-pipe. */
    circpad_event_padding_received(circ);
    log_notice(LD_OR,"Got padding cell!");
  } else {
    /* We received a non-padding cell on the edge */
    circpad_event_nonpadding_received(circ);
  }
}

/**
 * Deliver circpad events for relay cells sent from us.
 *
 * If this is a padding cell, update our padding stats
 * and deliver the event. Otherwise just deliver the event.
 */
void
circpad_deliver_sent_relay_cell_events(circuit_t *circ,
                                       uint8_t relay_command)
{
  /* Padding negotiate cells are ignored by the state machines
   * for simplicity. */
  if (relay_command == RELAY_COMMAND_PADDING_NEGOTIATE ||
      relay_command == RELAY_COMMAND_PADDING_NEGOTIATED) {
    return;
  }

  /* RELAY_COMMAND_DROP is the multi-hop (aka circuit-level) padding cell in
   * tor. (CELL_PADDING is a channel-level padding cell, which is not relayed
   * or processed here) */
  if (relay_command == RELAY_COMMAND_DROP) {
    rep_hist_padding_count_write(PADDING_TYPE_DROP);
    /* This is a padding cell sent from the client or from the middle node,
     * (because it's invoked from circuitpadding.c) */
    circpad_event_padding_sent(circ);
  } else {
    /* This is a non-padding cell sent from the client or from
     * this node. */
    circpad_event_nonpadding_sent(circ);
  }
}

/**
 * Free the machineinfo at an index
 */
static void
circpad_circuit_machineinfo_free_idx(circuit_t *circ, int idx)
{
  circpad_machineinfo_handle_free(circ->padding_handles[idx]);

  if (circ->padding_info[idx]) {
    circpad_machineinfo_handles_clear(circ->padding_info[idx]);
    tor_free(circ->padding_info[idx]->histogram);
    timer_free(circ->padding_info[idx]->padding_timer);
    tor_free(circ->padding_info[idx]);
  }
}

/**
 * Free all padding machines and mutable info associated with
 * circuit
 */
void
circpad_circuit_machineinfo_free(circuit_t *circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
    circpad_circuit_machineinfo_free_idx(circ, i);
  }
}

/**
 * Allocate a new mutable machineinfo structure.
 */
circpad_machineinfo_t *
circpad_circuit_machineinfo_new(circuit_t *on_circ, int machine_index)
{
  circpad_machineinfo_t *mi = tor_malloc_zero(sizeof(circpad_machineinfo_t));
  mi->machine_index = machine_index;
  mi->on_circ = on_circ;

  return mi;
}

static void
circpad_setup_machine_on_circ(circuit_t *on_circ, circpad_machine_t *machine)
{
  if (CIRCUIT_IS_ORIGIN(on_circ) && !machine->origin_side) {
    log_fn(LOG_WARN, LD_BUG,
           "Can't set up non-origin machine on origin circuit!");
    return;
  }

  if (!CIRCUIT_IS_ORIGIN(on_circ) && machine->origin_side) {
    log_fn(LOG_WARN, LD_BUG,
           "Can't set up origin machine on non-origin circuit!");
    return;
  }

  // XXX: BUG()?
  //tor_fragile_assert(on_circ->padding_machine[machine->machine_index]
  //   == NULL);
  //tor_fragile_assert(on_circ->padding_info[machine->machine_index]
  //   == NULL);

  on_circ->padding_info[machine->machine_index] =
      circpad_circuit_machineinfo_new(on_circ, machine->machine_index);
  on_circ->padding_machine[machine->machine_index] = machine;
}

static void
circpad_circ_client_machine_init(void)
{
  circpad_machine_t *circ_client_machine
      = tor_malloc_zero(sizeof(circpad_machine_t));

  // XXX: Better conditions..
  circ_client_machine->conditions.min_hops = 2;
  circ_client_machine->conditions.state_mask = CIRCPAD_STATE_ALL;
  circ_client_machine->conditions.purpose_mask = CIRCPAD_PURPOSE_ALL;

  circ_client_machine->target_hopnum = 2;
  circ_client_machine->origin_side = 1;

  circ_client_machine->transition_burst_events =
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  circ_client_machine->burst.transition_events[CIRCPAD_STATE_BURST] =
    CIRCPAD_TRANSITION_ON_PADDING_RECV |
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  /* If we are in burst state, and we send a non-padding cell, then we cancel
     the timer for the next padding cell:
     We dont want to send fake extends when actual extends are going on */
  circ_client_machine->burst.transition_cancel_events =
    CIRCPAD_TRANSITION_ON_NONPADDING_SENT;

  circ_client_machine->burst.transition_events[CIRCPAD_STATE_END] =
    CIRCPAD_TRANSITION_ON_BINS_EMPTY;

  // FIXME: Is this what we want?
  circ_client_machine->burst.token_removal = CIRCPAD_TOKEN_REMOVAL_HIGHER;

  // FIXME: Tune this histogram
  circ_client_machine->burst.histogram_len = 5;
  circ_client_machine->burst.start_usec = 500;
  circ_client_machine->burst.range_sec = 1;
  /* We have 5 tokens in the histogram, which means that all circuits will look
   * like they have 7 hops (since we start this machine after the second hop,
   * and tokens are decremented for any valid hops, and fake extends are
   * used after that -- 2+5==7). */
  circ_client_machine->burst.histogram[0] = 5;
  circ_client_machine->burst.histogram_total = 5;

  circ_client_machine->machine_num = smartlist_len(origin_padding_machines);
  smartlist_add(origin_padding_machines, circ_client_machine);
}

static void
circpad_circ_responder_machine_init(void)
{
  circpad_machine_t *circ_responder_machine
      = tor_malloc_zero(sizeof(circpad_machine_t));

  /* The relay-side doesn't care what hopnum it is, but for consistency,
   * let's match the client */
  circ_responder_machine->target_hopnum = 2;
  circ_responder_machine->origin_side = 0;

  /* XXX check if we need to setup token_removal */

  /* This is the settings of the state machine. In the future we are gonna
     serialize this into the consensus or the torrc */

  /* We transition to the burst state on padding receive and on non-padding
   * recieve */
  circ_responder_machine->transition_burst_events =
    CIRCPAD_TRANSITION_ON_PADDING_RECV |
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  /* Inside the burst state we _stay_ in the burst state when a non-padding
   * is sent */
  circ_responder_machine->burst.transition_events[CIRCPAD_STATE_BURST] =
    CIRCPAD_TRANSITION_ON_NONPADDING_SENT;

  /* Inside the burst state we transition to the gap state when we receive a
   * padding cell */
  circ_responder_machine->burst.transition_events[CIRCPAD_STATE_GAP] =
    CIRCPAD_TRANSITION_ON_PADDING_RECV;

  /* These describe the padding charasteristics when in burst state */

  /* use_rtt_estimate tries to estimate how long padding cells take to go from
     C->M, and uses that as what as the base of the histogram */
  circ_responder_machine->burst.use_rtt_estimate = 1;
  /* The histogram is 1 bin */
  circ_responder_machine->burst.histogram_len = 1;
  circ_responder_machine->burst.start_usec = 5000;
  circ_responder_machine->burst.range_sec = 10;
  /* During burst state we wait forever for padding to arrive.

     We are waiting for a padding cell from the client to come in, so that we
     respond, and we immitate how extend looks like */
  circ_responder_machine->burst.histogram[0] = 1; // Only infinity bin here
  circ_responder_machine->burst.histogram_total = 1;

  /* From the gap state, we _stay_ in the gap state, when we receive padding
   * or non padding */
  circ_responder_machine->gap.transition_events[CIRCPAD_STATE_GAP] =
    CIRCPAD_TRANSITION_ON_PADDING_RECV |
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  /* And from the gap state, we go to the end, when the bins are empty or a
   * non-padding cell is sent */
  circ_responder_machine->gap.transition_events[CIRCPAD_STATE_END] =
    CIRCPAD_TRANSITION_ON_BINS_EMPTY |
    CIRCPAD_TRANSITION_ON_NONPADDING_SENT;

  // FIXME: Tune this histogram

  /* The gap state is the delay you wait after you receive a padding cell
     before you send a padding response */
  circ_responder_machine->gap.use_rtt_estimate = 1;
  circ_responder_machine->gap.histogram_len = 6;
  circ_responder_machine->gap.start_usec = 5000;
  circ_responder_machine->gap.range_sec = 10;
  circ_responder_machine->gap.histogram[0] = 0;
  circ_responder_machine->gap.histogram[1] = 1;
  circ_responder_machine->gap.histogram[2] = 2;
  circ_responder_machine->gap.histogram[3] = 2;
  circ_responder_machine->gap.histogram[4] = 1;
  /* Total number of tokens */
  circ_responder_machine->gap.histogram_total = 6;

  circ_responder_machine->machine_num = smartlist_len(relay_padding_machines);
  smartlist_add(relay_padding_machines, circ_responder_machine);
}

/**
 * Initialize all of our padding machines.
 *
 * This is called at startup. It sets up some global machines, and then
 * loads some from torrc, and from the tor consensus.
 */
void
circpad_machines_init(void)
{
  // XXX: BUG()?
  //tor_fragile_assert(origin_padding_machines == NULL);
  //tor_fragile_assert(relay_padding_machines == NULL);
  origin_padding_machines = smartlist_new();
  relay_padding_machines = smartlist_new();

  circpad_circ_client_machine_init();
  circpad_circ_responder_machine_init();
}

/**
 * Free our padding machines
 */
void
circpad_machines_free(void)
{
  if (origin_padding_machines) {
    SMARTLIST_FOREACH(origin_padding_machines,
                      circpad_machine_t *,
                      m, tor_free(m));
    smartlist_free(origin_padding_machines);
  }

  if (relay_padding_machines) {
    SMARTLIST_FOREACH(relay_padding_machines,
                      circpad_machine_t *,
                      m, tor_free(m));
    smartlist_free(relay_padding_machines);
  }
}

/**
 * Check the Protover info to see if a node supports padding.
 */
static int
circpad_node_supports_padding(const node_t *node)
{
  if (node->rs) {
    log_fn(LOG_INFO, LD_CIRC, "Checking padding..");
    return node->rs->pv.supports_padding;
  }

  log_fn(LOG_INFO, LD_CIRC, "Empty routerstatus in padding check");
  return 0;
}

/**
 * Get a node_t for the nth hop in our circuit, starting from 1.
 */
static const node_t *
circuit_get_nth_hop(origin_circuit_t *circ, int hop)
{
  crypt_path_t *iter = circ->cpath;
  int i;

  for (i = 1; i < hop; i++) {
    iter = iter->next;

    // Did we wrap around?
    if (iter == circ->cpath)
      return NULL;

    if (iter->state != CPATH_STATE_OPEN)
      return NULL;
  }

  return node_get_by_id(iter->extend_info->identity_digest);
}

/**
 * Return true if a particular circuit supports padding
 * at the desired hop.
 */
static int
circpad_circuit_supports_padding(origin_circuit_t *circ,
                                 int target_hopnum)
{
  const node_t *hop;

  if (!(hop = circuit_get_nth_hop(circ, target_hopnum))) {
    return 0;
  }

  return circpad_node_supports_padding(hop);
}

/**
 * Try to negotiate padding.
 *
 * Returns 1 if successful (or already set up), 0 otherwise.
 */
int
circpad_negotiate_padding(origin_circuit_t *circ,
                          circpad_machine_num_t machine,
                          int target_hopnum,
                          int command)
{
  circpad_negotiate_t type;
  cell_t cell;
  ssize_t len;

  if (!circpad_circuit_supports_padding(circ, target_hopnum)) {
    return 0;
  }

  memset(&cell, 0, sizeof(cell_t));
  memset(&type, 0, sizeof(circpad_negotiate_t));
  // This gets reset to RELAY_EARLY appropriately by
  // relay_send_command_from_edge_. At least, it looks that way.
  // QQQ-MP-AP: Verify that.
  cell.command = CELL_RELAY;

  circpad_negotiate_set_command(&type, command);
  circpad_negotiate_set_version(&type, 0);
  circpad_negotiate_set_machine_type(&type, machine);

  if ((len = circpad_negotiate_encode(cell.payload, CELL_PAYLOAD_SIZE,
        &type)) < 0)
    return 0;

  return circpad_send_command_to_hop(circ, target_hopnum,
                                     RELAY_COMMAND_PADDING_NEGOTIATE,
                                     cell.payload, len) == 0;
}

/**
 * Try to negotiate padding.
 *
 * Returns 1 if successful (or already set up), 0 otherwise.
 */
int
circpad_padding_negotiated(circuit_t *circ,
                           circpad_machine_num_t machine,
                           int command,
                           int response)
{
  circpad_negotiated_t type;
  cell_t cell;
  ssize_t len;

  memset(&cell, 0, sizeof(cell_t));
  memset(&type, 0, sizeof(circpad_negotiated_t));
  // This gets reset to RELAY_EARLY appropriately by
  // relay_send_command_from_edge_. At least, it looks that way.
  // QQQ-MP-AP: Verify that.
  cell.command = CELL_RELAY;

  circpad_negotiated_set_command(&type, command);
  circpad_negotiated_set_response(&type, response);
  circpad_negotiated_set_version(&type, 0);
  circpad_negotiated_set_machine_type(&type, machine);

  if ((len = circpad_negotiated_encode(cell.payload, CELL_PAYLOAD_SIZE,
        &type)) < 0)
    return 0;

  /* Use relay_send because we're from the middle to the origin. We don't
   * need to specify a target hop or layer_hint. */
  return relay_send_command_from_edge(0, circ,
                                      RELAY_COMMAND_PADDING_NEGOTIATED,
                                      (void*)cell.payload,
                                      (size_t)len, NULL) == 0;
}

/**
 * Parse and react to a padding_negotiate cell.
 *
 * This is called at the middle node upon receipt of the client's choice of
 * state machine, so that it can use the requested state machine index, if
 * it is available.
 */
int
circpad_handle_padding_negotiate(circuit_t *circ, cell_t *cell)
{
  circpad_negotiate_t *negotiate;

  if (CIRCUIT_IS_ORIGIN(circ)) {
    log_fn(LOG_WARN, LD_PROTOCOL,
           "Padding negotiate cell unsupported at origin.");
    return -1;
  }

  if (circpad_negotiate_parse(&negotiate, cell->payload+RELAY_HEADER_SIZE,
                               CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE) < 0) {
    log_fn(LOG_WARN, LD_CIRC,
          "Received malformed PADDING_NEGOTIATE cell; "
          "dropping.");
    circpad_padding_negotiated(circ, negotiate->machine_type,
                               negotiate->command,
                               CIRCPAD_RESPONSE_ERR);
    circpad_negotiate_free(negotiate);
    return -1;
  }

  if (negotiate->command == CIRCPAD_COMMAND_STOP) {
    /* Find the machine corresponding to this machine type */
    for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
      if (circ->padding_machine[i]->machine_num == negotiate->machine_type) {
        circpad_circuit_machineinfo_free_idx(circ, i);
        circ->padding_machine[i] = NULL;
        circpad_padding_negotiated(circ, negotiate->machine_type,
                                   negotiate->command,
                                   CIRCPAD_RESPONSE_OK);
        circpad_negotiate_free(negotiate);
        return 0;
      }
    }
    log_fn(LOG_WARN, LD_CIRC,
          "Received circuit padding stop command for unknown machine.");
    circpad_padding_negotiated(circ, negotiate->machine_type,
                               negotiate->command,
                               CIRCPAD_RESPONSE_ERR);
    circpad_negotiate_free(negotiate);
    return -1;
  } else if (negotiate->command == CIRCPAD_COMMAND_START) {
    SMARTLIST_FOREACH_BEGIN(relay_padding_machines,
                            circpad_machine_t *,
                            m) {
      if (m->machine_num == negotiate->machine_type) {
        circpad_setup_machine_on_circ(circ, m);
        circpad_padding_negotiated(circ, negotiate->machine_type,
                                   negotiate->command,
                                   CIRCPAD_RESPONSE_OK);
        circpad_negotiate_free(negotiate);
        return 0;
      }
    } SMARTLIST_FOREACH_END(m);
  }

  circpad_padding_negotiated(circ, negotiate->machine_type,
                             negotiate->command,
                             CIRCPAD_RESPONSE_ERR);
  circpad_negotiate_free(negotiate);
  return -1;
}

/**
 * Parse and react to a padding_negotiated cell.
 *
 * This is called at the origin upon receipt of the middle's response
 * to our choice of state machine.
 */
int
circpad_handle_padding_negotiated(circuit_t *circ, cell_t *cell,
                                  crypt_path_t *layer_hint)
{
  circpad_negotiated_t *negotiated;

  if (!CIRCUIT_IS_ORIGIN(circ)) {
    log_fn(LOG_WARN, LD_PROTOCOL,
           "Padding negotiate cell unsupported at non-origin.");
    return -1;
  }

  /* Verify this came from the expected hop */
  if (!circpad_padding_is_from_expected_hop(circ, layer_hint)) {
    log_fn(LOG_WARN, LD_PROTOCOL,
           "Padding negotiated cell from wrong hop!");
    return -1;
  }

  if (circpad_negotiated_parse(&negotiated, cell->payload+RELAY_HEADER_SIZE,
                               CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE) < 0) {
    log_fn(LOG_WARN, LD_CIRC,
          "Received malformed PADDING_NEGOTIATED cell; "
          "dropping.");

    circpad_negotiated_free(negotiated);
    return -1;
  }

  if (negotiated->command == CIRCPAD_COMMAND_STOP) {
    for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
      if (circ->padding_machine[i] &&
          circ->padding_machine[i]->machine_num == negotiated->machine_type) {

        /* We only clear the padding machine if the padding_info is gone.
         * Otherwise, this machine was replaced since we sent
         * the stop. */
        if (circ->padding_info[i] == NULL)
          circ->padding_machine[i] = NULL;
      }
    }
  } else if (negotiated->command == CIRCPAD_COMMAND_START &&
             negotiated->response == CIRCPAD_RESPONSE_ERR) {
    // This can happen due to consensus drift.. free the machines
    // and be sad
    log_fn(LOG_INFO, LD_CIRC,
           "Middle node did not accept our padidng request.");
  }

  circpad_negotiated_free(negotiated);
  return 0;
}

/* Serialization */
// TODO: Should we use keyword=value here? Are there helpers for that?
static void
circpad_state_serialize(const circpad_state_t *state,
                        smartlist_t *chunks)
{
  smartlist_add_asprintf(chunks, " %u", state->histogram[0]);
  for (int i = 1; i < state->histogram_len; i++) {
    smartlist_add_asprintf(chunks, ",%u",
                           state->histogram[i]);
  }

  smartlist_add_asprintf(chunks, " 0x%x",
                         state->transition_cancel_events);

  for (int i = 0; i < CIRCPAD_NUM_STATES; i++) {
    smartlist_add_asprintf(chunks, ",0x%x",
                           state->transition_events[i]);
  }

  smartlist_add_asprintf(chunks, " %u %u",
                         state->use_rtt_estimate,
                         state->token_removal);
}

char *
circpad_machine_to_string(const circpad_machine_t *machine)
{
  smartlist_t *chunks = smartlist_new();
  char *out;

  smartlist_add_asprintf(chunks,
                         "0x%x ",
                         machine->transition_burst_events);
  smartlist_add_asprintf(chunks,
                         "0x%x",
                         machine->transition_gap_events);

  circpad_state_serialize(&machine->gap, chunks);
  circpad_state_serialize(&machine->burst, chunks);

  out = smartlist_join_strings(chunks, "", 0, NULL);

  SMARTLIST_FOREACH(chunks, char *, cp, tor_free(cp));
  smartlist_free(chunks);
  return out;
}

// XXX: Writeme
const circpad_machine_t *
circpad_string_to_machine(const char *str)
{
  (void)str;
  return NULL;
}

