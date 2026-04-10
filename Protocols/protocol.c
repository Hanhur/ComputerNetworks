#include "protocol.h"
#include <stdio.h>

/* Stub implementations for all protocol functions */

void wait_for_event(event_type *event) 
{
    /* In real code, this would block waiting for an event */
    /* For demo, just return frame_arrival */
    printf("wait_for_event: returning frame_arrival\n");
    *event = frame_arrival;
}

void from_network_layer(packet *p) 
{
    static int counter = 0;
    printf("from_network_layer: getting packet %d\n", counter);
    /* Fill with test data */
    for (int i = 0; i < MAX_PKT && i < 10; i++) 
    {
        p->data[i] = (unsigned char)(counter + i);
    }
    counter++;
}

void to_network_layer(packet *p) 
{
    printf("to_network_layer: delivering packet, first byte = %d\n", p->data[0]);
}

void from_physical_layer(frame *r) 
{
    printf("from_physical_layer: receiving frame\n");
    r->kind = data;
    r->seq = 0;
    r->ack = 0;
}

void to_physical_layer(frame *s) 
{
    printf("to_physical_layer: sending frame, kind = %d, seq = %u\n", s->kind, s->seq);
}

void start_timer(seq_nr k) 
{
    printf("start_timer: seq = %u\n", k);
}

void stop_timer(seq_nr k) 
{
    printf("stop_timer: seq = %u\n", k);
}

void start_ack_timer(void) 
{
    printf("start_ack_timer\n");
}

void stop_ack_timer(void) 
{
    printf("stop_ack_timer\n");
}

void enable_network_layer(void) 
{
    printf("enable_network_layer\n");
}

void disable_network_layer(void) 
{
    printf("disable_network_layer\n");
}