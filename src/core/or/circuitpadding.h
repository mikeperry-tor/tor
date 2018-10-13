/*
 * Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitpadding.h
 * \brief Header file for circuitpadding.c.
 **/
#ifndef TOR_CIRCUITPADDING_H
#define TOR_CIRCUITPADDING_H

#include "circpad_negotiation.h"
#include "lib/container/handles.h"
#include "lib/evloop/timers.h"

typedef struct circuit_t circuit_t;
typedef struct origin_circuit_t origin_circuit_t;
typedef struct cell_t cell_t;

/**
 * Circpad state specifier.
 *
 * Each circuit has up to two state machines, and each state
 * machine consists of these states. Machines transition between
 * these states using the event transition specifiers below.
 */
typedef enum {
  CIRCPAD_STATE_START = 0,
  CIRCPAD_STATE_BURST = 1,
  CIRCPAD_STATE_GAP = 2,
  CIRCPAD_STATE_END = 3
} circpad_statenum_t;
#define CIRCPAD_NUM_STATES  ((uint8_t)CIRCPAD_STATE_END+1)

/**
 * These constants form a bitfield to specify the types of events
 * that can cause transitions between state machine states.
 *
 * Note that SENT and RECV are relative to this endpoint. For
 * relays, SENT means packets destined towards the client and
 * RECV means packets destined towards the relay. On the client,
 * SENT means packets destined towards the relay, where as RECV
 * means packets destined towards the client.
 */
typedef enum {
  CIRCPAD_TRANSITION_ON_NONPADDING_RECV = 1<<0,
  CIRCPAD_TRANSITION_ON_NONPADDING_SENT = 1<<1,
  CIRCPAD_TRANSITION_ON_PADDING_SENT = 1<<2,
  CIRCPAD_TRANSITION_ON_PADDING_RECV = 1<<3,
  CIRCPAD_TRANSITION_ON_INFINITY = 1<<4,
  CIRCPAD_TRANSITION_ON_BINS_EMPTY = 1<<5
} circpad_transition_t;

/**
 * An infinite padding cell delay means don't schedule any padding --
 * simply wait until a different event triggers a transition.
 */
#define CIRCPAD_DELAY_INFINITE  (UINT32_MAX)

/**
 * Token removal strategy options.
 *
 * The WTF-PAD histograms are meant to specify a target distribution to shape
 * traffic towards. This is accomplished by removing tokens from the histogram
 * when either padding or non-padding cells are sent.
 *
 * When we see a non-padding cell at a particular time since the last cell, you
 * remove a token from the corresponding delay bin. These flags specify
 * which bin to choose if that bin is already empty.
 */
typedef enum {
  /** Don't remove any tokens */
  CIRCPAD_TOKEN_REMOVAL_NONE = 0,
  /** Remove from the first non-zero higher bin index when current is zero. */
  CIRCPAD_TOKEN_REMOVAL_HIGHER = 1,
  /** Remove from the first non-zero lower bin index when current is empty. */
  CIRCPAD_TOKEN_REMOVAL_LOWER = 2,
  /** Remove from the closest non-zero lower bin index in either direction
   *  when current is empty. */
  CIRCPAD_TOKEN_REMOVAL_CLOSEST = 3,
  /** Remove from the closest bin by time value (since bins are
   *  exponentially spaced). */
  CIRCPAD_TOKEN_REMOVAL_CLOSEST_USEC = 4
} circpad_removal_t;

/** The maximum length any histogram can be. */
#define CIRCPAD_MAX_HISTOGRAM_LEN 50

/**
 * A circuit padding state machine state.
 *
 * This struct describes the histograms and parameters of a single
 * state in the adaptive padding machine. Instances of this struct
 * exist in global circpad machine definitions that come from torrc
 * or the consensus, and are immutable.
 */
typedef struct circpad_state_t {
  /** how long the histogram is (in bins) */
  uint8_t histogram_len;
  /** histogram itself: an array of uint16s of tokens, whose
   * widths are exponentially spaced, in microseconds */
  uint16_t histogram[CIRCPAD_MAX_HISTOGRAM_LEN];
  /** total number of tokens */
  uint32_t histogram_total;
  /** microseconds of the first bin of histogram */
  uint32_t start_usec;
  /** the time value of the last bin of the histogram.
      so together they define the span of the delay */
  uint16_t range_sec;

  /**
   * This is a bitfield that specifies which direction and types
   * of traffic that cause us to remain in the current state. Cancel the
   * pending padding packet (if any), and then await the next event.
   *
   * Example: Cancel padding if I saw a regular data packet.
   */
  circpad_transition_t transition_cancel_events;

  /**
   * This is an array of bitfields that specifies which direction and
   * types of traffic that cause us to abort our scheduled packet and
   * switch to the state corresponding to the index of the array.
   *
   * Example: If the bins are empty (CIRCPAD_TRANSITION_ON_BINS_EMPTY) and that
   * bit is set in the burst state index, then transition to the burst state.
   */
  circpad_transition_t transition_events[CIRCPAD_NUM_STATES];

  /**
   * If true, estimate the RTT from this relay to the exit/website and add that
   * to start_usec for use as the histogram bin 0 start delay.
   *
   * Right now this is only supported for relay-side state machines.
   */
  uint8_t use_rtt_estimate;

  /** If true, remove tokens from the histogram upon padding and
   * non-padding activity.
   * XXX: Verify+clarify how this is different than token strategy NONE */
  circpad_removal_t token_removal;
} circpad_state_t;

/**
 * Mutable padding machine info.
 *
 * This structure contains mutable information about a padding
 * machine. The mutable information must be kept separate because
 * it exists per-circuit, where as the machines themselves are global.
 * This separation is done to conserve space in the circuit structure.
 *
 * This is the per-circuit state that changes regarding the global state
 * machine. Some parts of it are optional (ie NULL).
 */
typedef struct circpad_machineinfo_t {
  HANDLE_ENTRY(circpad_machineinfo, circpad_machineinfo_t);

  /** The callback pointer for the padding callbacks */
  tor_timer_t *padding_timer;

  /** The circuit for this machine */
  circuit_t *on_circ;

  /** The time at which we scheduled a non-padding packet.
   * Monotonic time in microseconds since system start.
   * This is 0 if padding is not currently scheduled.
   */
  uint64_t padding_was_scheduled_at_us;

  /** A mutable copy of the histogram for the current state.
   *  NULL if remove_tokens is false for that state */
  uint16_t *histogram;
  /** Length of the above histogram */
  uint8_t histogram_len;
  /** Remove token from this index upon sending padding */
  uint8_t chosen_bin;

  /** What state is this machine in? */
  circpad_statenum_t current_state;

  /**
   * The last time we got an event relevant to estimating
   * the RTT. Monotonic time in microseconds since system
   * start.
   */
  uint64_t last_received_time_us;

  /**
   * EWMA estimate of the RTT of the circuit from this hop
   * to the exit end. */
  uint32_t rtt_estimate;

  /**
   * If this is true, we have seen full duplex behavior.
   * Stop updating the RTT.
   */
  uint8_t stop_rtt_update : 1;

/** Max number of padding machines on each circuit. If changed,
 * also ensure the machine_index bitwith supports the new size. */
#define CIRCPAD_MAX_MACHINES    (2)
  /** Which padding machine index was this for.
   * (make sure changes to the bitwidth can support the
   * CIRCPAD_MAX_MACHINES define). */
  uint8_t machine_index : 1;

} circpad_machineinfo_t;

HANDLE_DECL(circpad_machineinfo, circpad_machineinfo_t,);

/** Helper macro to get an actual state machine from a machineinfo */
#define CIRCPAD_GET_MACHINE(machineinfo) \
    ((machineinfo)->on_circ->padding_machine[(machineinfo)->machine_index])

/** Global state machine structure from the consensus */
typedef struct circpad_machine_t {
  /** Transition to the burst state (from start) on the events that are set
   *  in this bitfield */
  circpad_transition_t transition_burst_events;
  /** Transition to the burst state (from start) on the events that are set
   *  in this bitfield */
  circpad_transition_t transition_gap_events;

  /** The burst state for this machine. XXX: Describe burst vs gap in terms
   * of interpacket delay. */
  circpad_state_t burst;

  /** The gap state. */
  circpad_state_t gap;

  /** Which hop in the circuit should we send padding to/from?
   *  1-indexed (ie: hop #1 is guard, #2 middle, #3 exit). */
  uint8_t target_hopnum;

  /** Non-zero if we've set up this machine */
  uint8_t is_initialized : 1;
} circpad_machine_t;

/** Padding decision upon receiving an event. (Just for unittest) */
typedef enum {
  CIRCPAD_WONTPAD_EVENT = 0,
  CIRCPAD_WONTPAD_CANCELED,
  CIRCPAD_NONPADDING_STATE,
  CIRCPAD_WONTPAD_INFINITY,
  CIRCPAD_PADDING_SCHEDULED,
  CIRCPAD_PADDING_SENT
} circpad_decision_t;

/**
 * The following are event call-in points that are of interest to
 * the state machines. They are called during cell processing. */
void circpad_event_nonpadding_sent(circuit_t *on_circ);
void circpad_event_nonpadding_received(circuit_t *on_circ);

void circpad_event_padding_sent(circuit_t *on_circ);
void circpad_event_padding_received(circuit_t *on_circ);

void circpad_event_infinity(circpad_machineinfo_t *mi);
void circpad_event_bins_empty(circpad_machineinfo_t *mi);

/* Machines for various usecases */

/**
 * This specifies a particular padding machine to use after negotiation.
 *
 * The constants for machine_num_t are in trunnel.
 * We want to be able to define extra numbers in the consensus/torrc, though.
 */
typedef uint8_t circpad_machine_num_t;

/* Toy state machines */
/* They attach a state machine to a circuit */
void circpad_circ_client_machine_setup(circuit_t *);
void circpad_circ_responder_machine_setup(circuit_t *on_circ);

void circpad_hs_serv_intro_machine_setup(circuit_t *);
void circpad_hs_client_intro_machine_setup(circuit_t *);

void circpad_adaptive_padding_machine_setup(circuit_t *);
void circpad_hs_serv_rend_machine_setup(circuit_t *);

void circpad_machines_free(circuit_t *circ);

int circpad_padding_is_from_expected_hop(circuit_t *circ,
                                         crypt_path_t *from_hop);

/** Serializaton functions for writing to/from torrc and consensus */
char *circpad_machine_to_string(const circpad_machine_t *machine);
const circpad_machine_t *circpad_string_to_machine(const char *str);

/* Padding negotiation between client and middle */
void circpad_event_padding_negotiate(circuit_t *circ, cell_t *cell);
int circpad_negotiate_padding(origin_circuit_t *circ,
                              circpad_machine_num_t machine, int echo);

#endif

