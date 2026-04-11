/* Протокол 6(выборочный повтор) принимает фреймы в любом порядке, но передает их сетевому уровню, соблюдая
порядок. С каждым неподтвержденным фреймом связан таймер. При срабатывании таймера передается повторно только
этот фрейм, а не все неподтвержденные фреймы, как в протоколе 5.*/

#include <stdio.h>
#include <stdlib.h>
#include "protocol.h"

#define MAX_SEQ 7 
#define NR_BUFS ((MAX_SEQ + 1) / 2)

boolean no_nak = true; /* negative acknowledgment (nak) not yet sent */
seq_nr oldest_frame = MAX_SEQ + 1;

/* Global variables for simulation */
static int timer_active = 0;
static int ack_timer_active = 0;
static int network_enabled = 1;

static boolean between(seq_nr a, seq_nr b, seq_nr c)
{
    return ((a <= b) && (b < c)) || ((c < a) && (a <= b)) || ((b < c) && (c < a));
}

static void send_frame(frame_kind fk, seq_nr frame_nr, seq_nr frame_expected, packet buffer[ ])
{
    frame s;
    s.kind = fk;
    if (fk == data) s.info = buffer[frame_nr % NR_BUFS];
    s.seq = frame_nr;
    s.ack = (frame_expected + MAX_SEQ) % (MAX_SEQ + 1);
    if (fk == nak) no_nak = false;
    to_physical_layer(&s);
    if (fk == data) start_timer(frame_nr % NR_BUFS);
    start_ack_timer();
}

/* ========== FUNCTION IMPLEMENTATIONS ========== */

void wait_for_event(event_type *event)
{
    char input;
    printf("\n=== EVENT SELECTION ===\n");
    printf("0: frame_arrival\n");
    printf("1: cksum_err (checksum error)\n");
    printf("2: timeout\n");
    printf("3: ack_timeout (acknowledgment timeout)\n");
    printf("4: network_layer_ready\n");
    printf("Your choice: ");
    scanf(" %c", &input);
    
    switch(input) {
        case '0': *event = frame_arrival; break;
        case '1': *event = cksum_err; break;
        case '2': *event = timeout; break;
        case '3': *event = ack_timeout; break;
        case '4': *event = network_layer_ready; break;
        default: *event = network_layer_ready;
    }
}

void from_network_layer(packet *p)
{
    static int packet_counter = 0;
    printf("  >> Packet received from network layer (packet #%d)\n", packet_counter);
    for(int i = 0; i < MAX_PKT && i < 10; i++) {
        p->data[i] = (packet_counter + i) % 256;
    }
    packet_counter++;
}

void to_network_layer(packet *p)
{
    printf("  >> Packet delivered to network layer\n");
}

void from_physical_layer(frame *r)
{
    static int frame_counter = 0;
    printf("  >> Frame received from physical layer\n");
    /* For simulation, create a test frame */
    r->kind = data;
    r->seq = frame_counter % (MAX_SEQ + 1);
    r->ack = 0;
    frame_counter++;
}

void to_physical_layer(frame *s)
{
    printf("  >> Frame sent to physical layer (type = %d, seq = %d, ack = %d)\n", s->kind, s->seq, s->ack);
}

void start_timer(seq_nr k)
{
    printf("  >> Timer started for frame #%d\n", k);
    timer_active = 1;
    oldest_frame = k;
}

void stop_timer(seq_nr k)
{
    printf("  >> Timer stopped for frame #%d\n", k);
    timer_active = 0;
}

void start_ack_timer(void)
{
    printf("  >> Acknowledgment timer started\n");
    ack_timer_active = 1;
}

void stop_ack_timer(void)
{
    printf("  >> Acknowledgment timer stopped\n");
    ack_timer_active = 0;
}

void enable_network_layer(void)
{
    if (!network_enabled) 
    {
        printf("  >> Network layer ENABLED\n");
        network_enabled = 1;
    }
}

void disable_network_layer(void)
{
    if (network_enabled) 
    {
        printf("  >> Network layer DISABLED\n");
        network_enabled = 0;
    }
}

/* ========== MAIN PROTOCOL FUNCTION ========== */

void protocol6(void)
{
    seq_nr ack_expected;
    seq_nr next_frame_to_send;
    seq_nr frame_expected;
    seq_nr too_far;
    int i;
    frame r;
    packet out_buf[NR_BUFS];
    packet in_buf[NR_BUFS];
    boolean arrived[NR_BUFS];
    seq_nr nbuffered;
    event_type event;
    
    printf("\n=== PROTOCOL 6 (SELECTIVE REPEAT) STARTED ===\n");
    printf("Window size: %d frames\n\n", NR_BUFS);
    
    enable_network_layer();
    ack_expected = 0;
    next_frame_to_send = 0;
    frame_expected = 0;
    too_far = NR_BUFS;
    nbuffered = 0;

    for (i = 0; i < NR_BUFS; i++) arrived[i] = false;

    while (1)
    {
        printf("\n--- State: ack_expected = %d, next_frame_to_send = %d, frame_expected = %d, nbuffered = %d ---\n", ack_expected, next_frame_to_send, frame_expected, nbuffered);
        
        wait_for_event(&event);

        switch (event)
        {
            case network_layer_ready:
                printf("\n*** EVENT: Network Layer Ready ***\n");
                nbuffered += 1;
                from_network_layer(&out_buf[next_frame_to_send % NR_BUFS]);
                send_frame(data, next_frame_to_send, frame_expected, out_buf);
                inc(next_frame_to_send);
                break;
                
            case frame_arrival:
                printf("\n*** EVENT: Frame Arrival ***\n");
                from_physical_layer(&r);
                if (r.kind == data)
                {
                    if ((r.seq != frame_expected) && no_nak)
                        send_frame(nak, 0, frame_expected, out_buf);
                    else 
                        start_ack_timer();
                    
                    if (between(frame_expected, r.seq, too_far) && (arrived[r.seq % NR_BUFS] == false))
                    {
                        arrived[r.seq % NR_BUFS] = true;
                        in_buf[r.seq % NR_BUFS] = r.info;

                        while (arrived[frame_expected % NR_BUFS])
                        {
                            to_network_layer(&in_buf[frame_expected % NR_BUFS]);
                            no_nak = true;
                            arrived[frame_expected % NR_BUFS] = false;
                            inc(frame_expected);
                            inc(too_far);
                            start_ack_timer();
                        }
                    }
                } 
                if ((r.kind == nak) && between(ack_expected, (r.ack + 1) % (MAX_SEQ + 1), next_frame_to_send))
                    send_frame(data, (r.ack + 1) % (MAX_SEQ + 1), frame_expected, out_buf);
                    
                while (between(ack_expected, r.ack, next_frame_to_send))
                {
                    nbuffered -= 1;
                    stop_timer(ack_expected % NR_BUFS);
                    inc(ack_expected);
                }
                break;
                
            case cksum_err:
                printf("\n*** EVENT: Checksum Error ***\n");
                if (no_nak) send_frame(nak, 0, frame_expected, out_buf);
                break;
                
            case timeout:
                printf("\n*** EVENT: Timeout ***\n");
                send_frame(data, oldest_frame, frame_expected, out_buf);
                break;
                
            case ack_timeout:
                printf("\n*** EVENT: Acknowledgment Timeout ***\n");
                send_frame(ack, 0, frame_expected, out_buf);
                break;
        }
        
        if (nbuffered < NR_BUFS) 
            enable_network_layer();
        else 
            disable_network_layer();
    }
}

/* ========== MAIN FUNCTION (ENTRY POINT) ========== */

int main(void)
{
    protocol6();
    return 0;
}