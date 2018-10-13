/* Copyright (c) 2017 The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "core/or/or.h"
#include "core/or/circuitpadding.h"
#include "core/or/circuitlist.h"
#include "core/or/relay.h"

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
circpad_machineinfo_t *circpad_machineinfo_new(circuit_t *on_circ,
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

/* Histogram helpers */
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

  if (bin >= state->histogram_len || bin < 0) {
    // XXX: Log, but only if less than 0. > histogram_len can happen..
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

  if (i == state->histogram_len-1) {
    fprintf(stderr, "Infinity pad!\n");
    if (state->token_removal != CIRCPAD_TOKEN_REMOVAL_NONE) {
      tor_assert(mi->histogram[i] > 0);
      mi->histogram[i]--;
    }

    // XXX: bins could be empty here..

    return CIRCPAD_DELAY_INFINITE; // Infinity: Don't send a padding packet
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

/* Remove a token from the bin corresponding to the delta since
 * last packet, or the next greater bin */
// TODO-MP-AP: remove from lower bin? lowest bin? closest bin?
// FIXME-MP-AP: Hidden service circuit machine may need both...
//   - XXX: Damnit, I forget why that was the case. Blah.
void
circpad_machine_remove_token(circpad_machineinfo_t *mi)
{
  const circpad_state_t *state = circpad_machine_current_state(mi);
  uint64_t current_time = monotime_absolute_usec();
  uint64_t target_bin_us;
  uint32_t histogram_total = 0;

  /* Dont remove any tokens if there was no padding scheduled */
  if (!mi->padding_was_scheduled_at_us) {
    return;
  }

  /* If we have scheduled padding some time in the future, we want to see what
     bin we are in at the current time */
  target_bin_us = current_time - mi->padding_was_scheduled_at_us;

  /* We are treating this non-padding cell as a padding cell, so we cancel
     padding */
  mi->padding_was_scheduled_at_us = 0;
  timer_disable(mi->padding_timer);

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
   * extra space is not worth this short loop iteration. */
  for (int b = 0; b < state->histogram_len; b++)
    histogram_total += mi->histogram[b];

  if (histogram_total == 0) {
    circpad_event_bins_empty(mi);
  }
}

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

  /* Check that enough hops are opened. */
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

void
circpad_send_padding_cell_for_callback(circpad_machineinfo_t *mi)
{
  mi->padding_was_scheduled_at_us = 0;

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
   * running total in machineinfo */
  if (mi->histogram && mi->histogram_len) {
    uint32_t histogram_total = 0;

    for (int b = 0; b < mi->histogram_len; b++)
      histogram_total += mi->histogram[b];

    if (histogram_total == 0) {
      circpad_event_bins_empty(mi);
    }
  }
}

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

  if (mi->padding_was_scheduled_at_us) {
    /* Cancel current timer (if any) */
    timer_disable(mi->padding_timer);
    mi->padding_was_scheduled_at_us = 0;
  }

  /* in_us = in microseconds */
  in_us = circpad_machine_sample_delay(mi);

  log_fn(LOG_INFO,LD_CIRC,"Padding in %u usec\n", in_us);

  if (in_us <= 0) {
    mi->padding_was_scheduled_at_us = monotime_absolute_usec();
    circpad_send_padding_cell_for_callback(mi);
    return CIRCPAD_PADDING_SENT;
  }

  // Don't schedule if we have infinite delay.
  if (in_us == CIRCPAD_DELAY_INFINITE) {
    // XXX-MP-AP: Return differently if we transition or not?
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

  // TODO-MP-AP: Unify with channelpadding counter
  //rep_hist_padding_count_timers(++total_timers_pending);

  mi->padding_was_scheduled_at_us = monotime_absolute_usec();

  return CIRCPAD_PADDING_SCHEDULED;
}

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
    if (mi->padding_was_scheduled_at_us) {
      /* Cancel current timer (if any) */
      timer_disable(mi->padding_timer);
      mi->padding_was_scheduled_at_us = 0;
      return CIRCPAD_WONTPAD_CANCELED;
    }
    return CIRCPAD_WONTPAD_EVENT;
  }

  /* See if we need to transition to any other states based on this event */
  for (circpad_statenum_t s = CIRCPAD_STATE_START; s < CIRCPAD_NUM_STATES;
       s++) {
    if (state->transition_events[s] & event) {
      /* If this is not the same state, switch and init tokens,
       * otherwise just reschedule padding. */
      if (mi->current_state != s) {
        mi->current_state = s;
        circpad_machine_setup_tokens(mi);
      }

      /* XXX do we always want to re-schedule padding after a sent/receive
       * cell? the code is rescheduling regarldess of whether the event was
       * sent/receive */
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

void
circpad_event_padding_sent(circuit_t *on_circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
       i++) {
    circpad_machine_transition(on_circ->padding_info[i],
                             CIRCPAD_TRANSITION_ON_PADDING_SENT);
  }
}

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

void
circpad_event_infinity(circpad_machineinfo_t *mi)
{
  circpad_statenum_t state = mi->current_state;
  circpad_machine_transition(mi, CIRCPAD_TRANSITION_ON_INFINITY);

  // If we didn't transition, send bins_empty if empty..
  // XXX-MP-AP: This is kind of a hacky way to detect transition...
  // Maybe the transition function should return transition information
  // instead of padding decisions..
  if (state == mi->current_state) {
    if (mi->histogram && mi->histogram_len) {
      uint32_t histogram_total = 0;

      for (int b = 0; b < mi->histogram_len; b++)
        histogram_total += mi->histogram[b];

      if (histogram_total == 0) {
        fprintf(stderr, "Bins empty after infnity!\n");
        circpad_event_bins_empty(mi);
      }
    }
  }
}

void
circpad_event_bins_empty(circpad_machineinfo_t *mi)
{
  if (!circpad_machine_transition(mi, CIRCPAD_TRANSITION_ON_BINS_EMPTY)) {
    /* If we dont transition, then we refill the tokens */
    circpad_machine_setup_tokens(mi);
  }
}

/**
 * Event callback to tell us that we have received a padding_negotiate
 * cell.
 *
 * This event is called at the middle node upon receipt of the client's
 * choice of state machine, so that it can use the requested state machine
 * index, if it is available.
 */
void
circpad_event_padding_negotiate(circuit_t *circ, cell_t *cell)
{
  circpad_negotiate_t *negotiate;

  if (circpad_negotiate_parse(&negotiate, cell->payload+RELAY_HEADER_SIZE,
                               CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE) < 0) {
    log_fn(LOG_WARN, LD_CIRC,
          "Received malformed PADDING_NEGOTIATE cell; "
          "dropping.");

    return;
  }

  if (negotiate->command == CIRCPAD_COMMAND_STOP) {
    circpad_machines_free(circ);
  } else if (negotiate->command == CIRCPAD_COMMAND_START) {
    // TODO-MP-AP: Support the other machine types..

    /* These are the built-in machines */
    switch (negotiate->machine_type) {
      case CIRCPAD_MACHINE_CIRC_SETUP:
        circpad_circ_responder_machine_setup(circ);
        break;
      case CIRCPAD_MACHINE_HS_CLIENT_INTRO:
        break;
      case CIRCPAD_MACHINE_HS_SERVICE_INTRO:
        break;
      case CIRCPAD_MACHINE_HS_SERVICE_REND:
        break;
      case CIRCPAD_MACHINE_WTF_PAD:
        break;
      default:
        break;
    }
  }

  /* If the other end requested an echo, send one. */
  if (negotiate->echo_request) {
    relay_send_command_from_edge(0, circ, RELAY_COMMAND_DROP, NULL, 0, NULL);
  }

  circpad_negotiate_free(negotiate);
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

void
circpad_machines_free(circuit_t *circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
    circpad_machineinfo_handle_free(circ->padding_handles[i]);

    if (circ->padding_info[i]) {
      circpad_machineinfo_handles_clear(circ->padding_info[i]);
      tor_free(circ->padding_info[i]->histogram);
      timer_free(circ->padding_info[i]->padding_timer);
      tor_free(circ->padding_info[i]);
    }
  }
}

circpad_machineinfo_t *
circpad_machineinfo_new(circuit_t *on_circ, int machine_index)
{
  circpad_machineinfo_t *mi = tor_malloc_zero(sizeof(circpad_machineinfo_t));
  mi->machine_index = machine_index;
  mi->on_circ = on_circ;

  return mi;
}

/* Machines for various usecases */
static circpad_machine_t circ_client_machine;
void
circpad_circ_client_machine_setup(circuit_t *on_circ)
{
  /* Free the old machines (if any) */
  circpad_machines_free(on_circ);

  on_circ->padding_machine[0] = &circ_client_machine;
  on_circ->padding_info[0] = circpad_machineinfo_new(on_circ, 0);

  if (circ_client_machine.is_initialized)
    return;

  circ_client_machine.target_hopnum = 2;

  circ_client_machine.transition_burst_events =
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  circ_client_machine.burst.transition_events[CIRCPAD_STATE_BURST] =
    CIRCPAD_TRANSITION_ON_PADDING_RECV |
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  /* If we are in burst state, and we send a non-padding cell, then we cancel
     the timer for the next padding cell:
     We dont want to send fake extends when actual extends are going on */
  circ_client_machine.burst.transition_cancel_events =
    CIRCPAD_TRANSITION_ON_NONPADDING_SENT;

  circ_client_machine.burst.transition_events[CIRCPAD_STATE_END] =
    CIRCPAD_TRANSITION_ON_BINS_EMPTY;

  // FIXME: Is this what we want?
  circ_client_machine.burst.token_removal = CIRCPAD_TOKEN_REMOVAL_HIGHER;

  // FIXME: Tune this histogram
  circ_client_machine.burst.histogram_len = 5;
  circ_client_machine.burst.start_usec = 500;
  circ_client_machine.burst.range_sec = 1;
  /* We have 5 tokens in the histogram, which means that all circuits will look
   * like they have 7 hops (since we start this machine after the second hop,
   * and tokens are decremented for any valid hops, and fake extends are
   * used after that -- 2+5==7).
   *
   * XXX: Is this true? We may decrement this on both send+recieve of real
   * extend cells, as per XXX in circpad_machine_transition() above :/ */
  circ_client_machine.burst.histogram[0] = 5;
  circ_client_machine.burst.histogram_total = 5;

  circ_client_machine.is_initialized = 1;

  return;
}

static circpad_machine_t circ_responder_machine;
void
circpad_circ_responder_machine_setup(circuit_t *on_circ)
{
  /* Free the old machines (if any) */
  circpad_machines_free(on_circ);

  on_circ->padding_machine[0] = &circ_responder_machine;
  on_circ->padding_info[0] = circpad_machineinfo_new(on_circ, 0);

  if (circ_responder_machine.is_initialized)
    return;

  /* The relay-side doesn't care what hopnum it is, but for consistency,
   * let's match the client */
  circ_client_machine.target_hopnum = 2;

  /* XXX check if we need to setup token_removal */

  /* This is the settings of the state machine. In the future we are gonna
     serialize this into the consensus or the torrc */

  /* We transition to the burst state on padding receive and on non-padding
   * recieve */
  circ_responder_machine.transition_burst_events =
    CIRCPAD_TRANSITION_ON_PADDING_RECV |
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  /* Inside the burst state we _stay_ in the burst state when a non-padding
   * is sent */
  circ_responder_machine.burst.transition_events[CIRCPAD_STATE_BURST] =
    CIRCPAD_TRANSITION_ON_NONPADDING_SENT;

  /* Inside the burst state we transition to the gap state when we receive a
   * padding cell */
  circ_responder_machine.burst.transition_events[CIRCPAD_STATE_GAP] =
    CIRCPAD_TRANSITION_ON_PADDING_RECV;

  /* These describe the padding charasteristics when in burst state */

  /* use_rtt_estimate tries to estimate how long padding cells take to go from
     C->M, and uses that as what as the base of the histogram */
  circ_responder_machine.burst.use_rtt_estimate = 1;
  /* The histogram is 1 bin */
  circ_responder_machine.burst.histogram_len = 1;
  circ_responder_machine.burst.start_usec = 5000;
  circ_responder_machine.burst.range_sec = 10;
  /* During burst state we wait forever for padding to arrive.

     We are waiting for a padding cell from the client to come in, so that we
     respond, and we immitate how extend looks like */
  circ_responder_machine.burst.histogram[0] = 1; // Only infinity bin here
  circ_responder_machine.burst.histogram_total = 1;

  /* From the gap state, we _stay_ in the gap state, when we receive padding
   * or non padding */
  circ_responder_machine.gap.transition_events[CIRCPAD_STATE_GAP] =
    CIRCPAD_TRANSITION_ON_PADDING_RECV |
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  /* And from the gap state, we go to the end, when the bins are empty or a
   * non-padding cell is sent */
  circ_responder_machine.gap.transition_events[CIRCPAD_STATE_END] =
    CIRCPAD_TRANSITION_ON_BINS_EMPTY |
    CIRCPAD_TRANSITION_ON_NONPADDING_SENT;

  // FIXME: Tune this histogram

  /* The gap state is the delay you wait after you receive a padding cell
     before you send a padding response */
  circ_responder_machine.gap.use_rtt_estimate = 1;
  circ_responder_machine.gap.histogram_len = 6;
  circ_responder_machine.gap.start_usec = 5000;
  circ_responder_machine.gap.range_sec = 10;
  circ_responder_machine.gap.histogram[0] = 0;
  circ_responder_machine.gap.histogram[1] = 1;
  circ_responder_machine.gap.histogram[2] = 2;
  circ_responder_machine.gap.histogram[3] = 2;
  circ_responder_machine.gap.histogram[4] = 1;
  /* Total number of tokens */
  circ_responder_machine.gap.histogram_total = 6;

  circ_responder_machine.is_initialized = 1;

  return;
}

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

static int
circpad_circuit_supports_padding(origin_circuit_t *circ)
{
  const node_t *hop;

  if (!(hop = circuit_get_nth_hop(circ, 2))) {
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
                          circpad_machine_num_t machine, int echo)
{
  circpad_negotiate_t type;
  cell_t cell;
  ssize_t len;

  // If we have a padding machine, we already did this.
  /* This check prevents us from making a new machine for every cell.
   * XXX: Maybe this means we need better event differentiation? */
  // XXX: What about more than one machine?
  if (TO_CIRCUIT(circ)->padding_machine[0]) {
    return 1;
  }

  if (!circpad_circuit_supports_padding(circ)) {
    return 0;
  }

  memset(&cell, 0, sizeof(cell_t));
  memset(&type, 0, sizeof(circpad_negotiate_t));
  // This gets reset to RELAY_EARLY appropriately by
  // relay_send_command_from_edge_. At least, it looks that way.
  // QQQ-MP-AP: Verify that.
  cell.command = CELL_RELAY;

  circpad_negotiate_set_command(&type, CIRCPAD_COMMAND_START);
  circpad_negotiate_set_version(&type, 0);
  circpad_negotiate_set_machine_type(&type, machine);
  circpad_negotiate_set_echo_request(&type, echo);

  if ((len = circpad_negotiate_encode(cell.payload, CELL_PAYLOAD_SIZE,
        &type)) < 0)
    return -1;

  /* Set up our own machine before telling the other side */
  switch (machine) {
    case CIRCPAD_MACHINE_CIRC_SETUP:
      /* and this is the setup of the machine on the client side */
      circpad_circ_client_machine_setup(TO_CIRCUIT(circ));
      break;
    case CIRCPAD_MACHINE_HS_CLIENT_INTRO:
      break;
    case CIRCPAD_MACHINE_HS_SERVICE_INTRO:
      break;
    case CIRCPAD_MACHINE_HS_SERVICE_REND:
      break;
    case CIRCPAD_MACHINE_WTF_PAD:
      break;
    default:
      break;
  }

  return circpad_send_command_to_hop(circ,
                                     TO_CIRCUIT(circ)->
                                       padding_machine[0]->target_hopnum,
                                     RELAY_COMMAND_PADDING_NEGOTIATE,
                                     cell.payload, len) == 0;
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

