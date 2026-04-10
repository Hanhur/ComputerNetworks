#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>

// Override MAX_SEQ for this implementation (1-bit sliding window)
#undef MAX_SEQ
#define MAX_SEQ 1

// ============= FUNCTION IMPLEMENTATIONS =============

void wait_for_event(event_type *event) 
{
    static int call_count = 0;
    call_count++;
    
    printf("  [WAIT] Waiting for event...\n");
    
    // Simulating various events
    if (call_count == 1) 
    {
        *event = frame_arrival;
        printf("  [WAIT] Event: frame_arrival (frame received)\n");
    } 
    else if (call_count == 2) 
    {
        *event = timeout;
        printf("  [WAIT] Event: timeout\n");
    } 
    else if (call_count == 3) 
    {
        *event = frame_arrival;
        printf("  [WAIT] Event: frame_arrival (frame received)\n");
    } 
    else 
    {
        *event = timeout;
        printf("  [WAIT] Event: timeout\n");
        call_count = 0; // Reset to repeat the cycle
    }
}

void from_network_layer(packet *p) 
{
    static int packet_num = 0;
    printf("  [NETWORK] Packet received from network layer #%d\n", packet_num);
    sprintf((char*)p->data, "Packet_%d", packet_num++);
}

void to_network_layer(packet *p) 
{
    printf("  [NETWORK] Packet delivered to network layer: %s\n", (char*)p->data);
}

void from_physical_layer(frame *r) 
{
    static int frame_num = 0;
    printf("  [PHYSICAL] Frame received from physical layer\n");
    r->kind = data;
    r->seq = frame_num % 2;
    r->ack = (frame_num + 1) % 2;
    printf("  [PHYSICAL] Frame: kind = %d, seq = %d, ack = %d\n", r->kind, r->seq, r->ack);
    frame_num++;
}

void to_physical_layer(frame *s) 
{
    printf("  [PHYSICAL] Sending frame to physical layer\n");
    printf("  [PHYSICAL] Frame: kind = %d, seq = %d, ack = %d\n", s->kind, s->seq, s->ack);
}

void start_timer(seq_nr k) 
{
    printf("  [TIMER] Timer started for seq = %d\n", k);
}

void stop_timer(seq_nr k) 
{
    printf("  [TIMER] Timer stopped for seq = %d\n", k);
}

void start_ack_timer(void) 
{
    printf("  [TIMER] ACK timer started\n");
}

void stop_ack_timer(void) 
{
    printf("  [TIMER] ACK timer stopped\n");
}

void enable_network_layer(void) 
{
    printf("  [LAYER] Network layer ENABLED\n");
}

void disable_network_layer(void) 
{
    printf("  [LAYER] Network layer DISABLED\n");
}

// ============= SENDER PROTOCOL (Sliding Window) =============

void sender3(void) 
{
    seq_nr next_frame_to_send;
    frame s;
    packet buffer;
    event_type event;
    int retransmissions = 0;

    printf("\n=== SENDER STARTED (sender3) ===\n");
    
    next_frame_to_send = 0;
    from_network_layer(&buffer);
    printf("\n");

    while (1) 
    {  // Using 1 instead of true for compatibility
        s.info = buffer;
        s.seq = next_frame_to_send;
        s.kind = data;
        s.ack = (next_frame_to_send == 0) ? 1 : 0;
        
        to_physical_layer(&s);
        start_timer(s.seq);
        wait_for_event(&event);
        printf("\n");

        if (event == frame_arrival) 
        {
            from_physical_layer(&s);
            
            if (s.ack == next_frame_to_send) 
            {
                stop_timer(s.ack);
                printf("  [SENDER] Acknowledgement received for frame #%d\n", next_frame_to_send);
                
                if (retransmissions > 0) 
                {
                    printf("  [SENDER] Transmitted after %d retransmissions\n", retransmissions);
                    retransmissions = 0;
                }
                
                from_network_layer(&buffer);
                inc(next_frame_to_send);
            } 
            else 
            {
                printf("  [SENDER] Invalid acknowledgement (expected %d, received %d)\n", next_frame_to_send, s.ack);
            }
        } 
        else if (event == timeout) 
        {
            printf("  [SENDER] TIMEOUT! Retransmitting frame #%d\n", next_frame_to_send);
            retransmissions++;
        }
        printf("\n");
    }
}

// ============= RECEIVER PROTOCOL =============

void receiver3(void) 
{
    seq_nr frame_expected;
    frame r, s;
    event_type event;
    int frames_received = 0;

    printf("\n=== RECEIVER STARTED (receiver3) ===\n");
    
    frame_expected = 0;

    while (1) 
    {
        wait_for_event(&event);
        printf("\n");

        if (event == frame_arrival) 
        {
            from_physical_layer(&r);
            printf("  [RECEIVER] Expected frame #%d, received frame #%d\n", frame_expected, r.seq);

            if (r.seq == frame_expected) 
            {
                to_network_layer(&r.info);
                printf("  [RECEIVER] Frame #%d accepted and delivered\n", frame_expected);
                inc(frame_expected);
                frames_received++;
                printf("  [RECEIVER] Frames received: %d\n", frames_received);
            } 
            else 
            {
                printf("  [RECEIVER] Frame #%d rejected (expected #%d)\n", r.seq, frame_expected);
            }

            s.ack = frame_expected;
            s.kind = ack;
            s.seq = 0;
            to_physical_layer(&s);
            printf("  [RECEIVER] Acknowledgement ACK = %d sent\n", s.ack);
        }
        printf("\n");
    }
}

// ============= DEMONSTRATION FUNCTION =============

void demonstrate_protocol(void) 
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║     SLIDING WINDOW PROTOCOL (ALGORITHM 3)                ║\n");
    printf("║     WITH ACKNOWLEDGEMENTS AND TIMEOUTS                   ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    
    printf("\nThe protocol works as follows:\n");
    printf("1. Sender transmits a frame with a sequence number\n");
    printf("2. Starts a timer\n");
    printf("3. Waits for acknowledgement from the receiver\n");
    printf("4. On timeout - retransmits the frame\n");
    printf("5. On correct acknowledgement - transmits the next frame\n\n");
    
    printf("SENDER DEMONSTRATION:\n");
    printf("--------------------------------\n");
    
    // Run sender for 3 iterations using a limited loop
    seq_nr next_frame_to_send = 0;
    frame s;
    packet buffer;
    
    from_network_layer(&buffer);
    
    for (int iteration = 0; iteration < 3; iteration++) 
    {
        printf("\n--- Iteration %d ---\n", iteration + 1);
        s.info = buffer;
        s.seq = next_frame_to_send;
        s.kind = data;
        to_physical_layer(&s);
        start_timer(s.seq);
        
        // Simulate receiving acknowledgement
        printf("  [DEMO] Acknowledgement received!\n");
        stop_timer(s.seq);
        from_network_layer(&buffer);
        inc(next_frame_to_send);
    }
    
    printf("\nRECEIVER DEMONSTRATION:\n");
    printf("--------------------------------\n");
    
    seq_nr frame_expected = 0;
    frame r, s2;
    
    for (int iteration = 0; iteration < 3; iteration++) 
    {
        printf("\n--- Iteration %d ---\n", iteration + 1);
        printf("  [DEMO] Expected frame #%d\n", frame_expected);
        
        // Simulate receiving a frame
        r.seq = frame_expected;
        printf("  [DEMO] Received frame #%d\n", r.seq);
        
        if (r.seq == frame_expected) 
        {
            printf("  [DEMO] Frame accepted!\n");
            inc(frame_expected);
        }
        
        s2.ack = frame_expected;
        printf("  [DEMO] Acknowledgement ACK = %d sent\n", s2.ack);
    }
}

// ============= MAIN FUNCTION =============

int main(void) 
{
    int choice;
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║           DATA TRANSFER PROTOCOL SIMULATION                ║\n");
    printf("║              SLIDING WINDOW (ALGORITHM 3)                  ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    printf("\nSelect operation mode:\n");
    printf("1. Protocol demonstration\n");
    printf("2. Run sender (sender3)\n");
    printf("3. Run receiver (receiver3)\n");
    printf("4. Full simulation (sender + receiver)\n");
    printf("0. Exit\n");
    printf("\nYour choice: ");
    
    scanf("%d", &choice);
    
    switch(choice) 
    {
        case 1:
            demonstrate_protocol();
            break;
        case 2:
            printf("\nWARNING: Sender will run in an infinite loop!\n");
            printf("Press Ctrl+C to stop\n\n");
            printf("Press Enter to continue...");
            getchar();
            getchar();
            sender3();
            break;
        case 3:
            printf("\nWARNING: Receiver will run in an infinite loop!\n");
            printf("Press Ctrl+C to stop\n\n");
            printf("Press Enter to continue...");
            getchar();
            getchar();
            receiver3();
            break;
        case 4:
            printf("\n=== STARTING FULL SIMULATION ===\n");
            printf("(Real simulation requires multi-threading)\n");
            printf("This demonstration shows the basic logic:\n\n");
            demonstrate_protocol();
            break;
        default:
            printf("Exiting program.\n");
            return 0;
    }
    
    printf("\nProgram finished.\n");
    return 0;
}