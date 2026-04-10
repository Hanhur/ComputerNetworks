#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulation variables
static frame simulated_frame;
static int frame_ready = 0;
static int timer_active = 0;
static seq_nr current_timer_seq = 0;
static int simulation_complete = 0;
static int max_iterations = 1; // Send only 5 packets
static int packet_count = 0;

// Event handling
void wait_for_event(event_type *event) 
{
    static int step = 0;
    
    if (simulation_complete) 
    {
        *event = network_layer_ready;
        return;
    }
    
    if (step == 0) 
    {
        *event = network_layer_ready;  // Start with data ready
    } 
    else if (frame_ready) 
    {
        // Check for checksum error simulation (10% chance)
        if (rand() % 10 == 0) 
        {
            *event = cksum_err;
        } 
        else 
        {
            *event = frame_arrival;
        }
        frame_ready = 0;
    } 
    else if (timer_active) 
    {
        *event = timeout;
        timer_active = 0;
    } 
    else 
    {
        *event = network_layer_ready;
    }
    step++;
}

// Network layer simulation
void from_network_layer(packet *p) 
{
    static int data = 0;
    
    if (packet_count >= max_iterations) 
    {
        simulation_complete = 1;
        printf("\n=== All packets have been sent. Protocol complete. ===\n");
        return;
    }
    
    memset(p->data, data++, MAX_PKT);
    printf("From network layer: sending packet %d\n", data-1);
}

void to_network_layer(packet *p) 
{
    printf("To network layer: received packet with data: %d\n", p->data[0]);
}

// Physical layer simulation
void from_physical_layer(frame *r) 
{
    memcpy(r, &simulated_frame, sizeof(frame));
    printf("From physical layer: received frame seq = %d, ack = %d\n", r->seq, r->ack);
}

void to_physical_layer(frame *s) 
{
    memcpy(&simulated_frame, s, sizeof(frame));
    frame_ready = 1;
    printf("To physical layer: sending frame seq = %d, ack = %d\n", s->seq, s->ack);
}

// Timer simulation
void start_timer(seq_nr k) 
{
    timer_active = 1;
    current_timer_seq = k;
    printf("Timer started for seq = %d\n", k);
}

void stop_timer(seq_nr k) 
{
    timer_active = 0;
    printf("Timer stopped for seq = %d\n", k);
}

void start_ack_timer(void) 
{
    printf("ACK timer started\n");
}

void stop_ack_timer(void) 
{
    printf("ACK timer stopped\n");
}

// Network layer control
void enable_network_layer(void) 
{
    printf("Network layer enabled\n");
}

void disable_network_layer(void) 
{
    printf("Network layer disabled\n");
}

// Main protocol function
void protocol4(void)
{
    seq_nr next_frame_to_send;
    seq_nr frame_expected;
    frame r, s;
    packet buffer;
    event_type event;

    next_frame_to_send = 0;
    frame_expected = 0;
    from_network_layer(&buffer);
    
    if (simulation_complete) return;
    
    s.info = buffer;
    s.seq = next_frame_to_send;
    s.ack = 1 - frame_expected;
    to_physical_layer(&s);
    start_timer(s.seq);

    while (!simulation_complete)
    {
        wait_for_event(&event);
        
        printf("Event received: %d\n", event);
        
        switch (event) 
        {
            case frame_arrival:
                from_physical_layer(&r);
                
                if (r.seq == frame_expected)
                {
                    to_network_layer(&r.info);
                    inc(frame_expected);
                }
                
                if (r.ack == next_frame_to_send)
                {
                    stop_timer(r.ack);
                    packet_count++;
                    from_network_layer(&buffer);
                    
                    if (simulation_complete) break;
                    
                    inc(next_frame_to_send);
                }
                
                if (!simulation_complete) 
                {
                    s.info = buffer;
                    s.seq = next_frame_to_send;
                    s.ack = 1 - frame_expected;
                    
                    to_physical_layer(&s);
                    start_timer(s.seq);
                }
                break;
                
            case cksum_err:
                printf("Checksum error! Frame corrupted.\n");
                break;
                
            case timeout:
                printf("Timeout! Retransmitting frame seq = %d\n", s.seq);
                if (!simulation_complete) 
                {
                    to_physical_layer(&s);
                    start_timer(s.seq);
                }
                break;
                
            case network_layer_ready:
                break;
        }
    }
    
    printf("\n=== The protocol has been stopped. ===\n");
}

// Main entry point
int main() 
{
    printf("Starting Single Bit Sliding Window Protocol (Stop-and-Wait)\n");
    printf("Will send %d packets then exit\n", max_iterations);
    printf("===========================================================\n\n");
    
    srand(42); // Seed for reproducible simulation
    
    protocol4(); // Will exit after sending all packets
    
    printf("\nPress any key to exit...");
    getchar();
    
    return 0;
}