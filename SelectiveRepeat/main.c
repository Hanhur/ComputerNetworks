/* Протокол 5(конвейерный) допускает наnичие нескоnьких неподтвержденных фреймов. Оmравитеnь может передать
до MAX_SEQ фреймов, не ожидая подтверждения. Кроме того, в отnичие от предыдущих протокоnов, не предпоnагается,
что у сетевого уровня всегда есть новые пакеты. При появлении нового пакета сетевой уровень инициирует событие
пetwork_layer_ready. */

#include <stdio.h>
#include <stdlib.h>
#include "protocol.h"

#define MAX_SEQ 7

/* Global variables for simulation */
static int timer_running = 0;
static seq_nr current_timer_seq = 0;
static int network_enabled = 1;
static int packet_counter = 0;
static int frame_counter = 0;

/* Protocol function implementations */
void wait_for_event(event_type *event)
{
    /* Simple simulation - generate events in sequence */
    static int event_cycle = 0;
    
    event_cycle++;
    
    if (event_cycle <= 3) 
    {
        *event = network_layer_ready;
        printf("Event: network_layer_ready\n");
    } 
    else if (event_cycle == 4) 
    {
        *event = frame_arrival;
        printf("Event: frame_arrival\n");
    } 
    else if (event_cycle == 5) 
    {
        *event = timeout;
        printf("Event: timeout\n");
    } 
    else 
    {
        *event = network_layer_ready;
        printf("Event: network_layer_ready\n");
        if (event_cycle > 10) event_cycle = 0;
    }
}

void from_network_layer(packet *p)
{
    printf("from_network_layer: received packet #%d\n", packet_counter);
    for (int i = 0; i < 10 && i < MAX_PKT; i++) {
        p->data[i] = packet_counter + i;
    }
    packet_counter++;
}

void to_network_layer(packet *p)
{
    printf("to_network_layer: delivered packet with first byte %d\n", p->data[0]);
}

void from_physical_layer(frame *r)
{
    /* Simulation of frame reception */
    static seq_nr last_seq = 0;
    r->seq = last_seq;
    r->ack = last_seq;
    r->kind = data;
    printf("from_physical_layer: received frame seq = %d, ack = %d\n", r->seq, r->ack);
    last_seq = (last_seq + 1) % (MAX_SEQ + 1);
}

void to_physical_layer(frame *s)
{
    printf("to_physical_layer: sent frame seq = %d, ack = %d\n", s->seq, s->ack);
    frame_counter++;
}

void start_timer(seq_nr k)
{
    timer_running = 1;
    current_timer_seq = k;
    printf("start_timer: started timer for seq = %d\n", k);
}

void stop_timer(seq_nr k)
{
    timer_running = 0;
    printf("stop_timer: stopped timer for seq = %d\n", k);
}

void start_ack_timer(void)
{
    printf("start_ack_timer: started ACK timer\n");
}

void stop_ack_timer(void)
{
    printf("stop_ack_timer: stopped ACK timer\n");
}

void enable_network_layer(void)
{
    network_enabled = 1;
    printf("enable_network_layer: network layer ENABLED\n");
}

void disable_network_layer(void)
{
    network_enabled = 0;
    printf("disable_network_layer: network layer DISABLED\n");
}

/* Between function */
static boolean between(seq_nr a, seq_nr b, seq_nr c)
{
    /* Returns true if a <= b < c cyclically; otherwise false */
    if (((a <= b) && (b < c)) || ((c < a) && (a <= b)) || ((b < c) && (c < a)))
        return(true);
    else
        return(false);
}

/* Send data function */
static void send_data(seq_nr frame_nr, seq_nr frame_expected, packet buffer[])
{
    /* Prepare and send an information frame */
    frame s;
    s.info = buffer[frame_nr];
    s.seq = frame_nr;
    s.ack = (frame_expected + MAX_SEQ) % (MAX_SEQ + 1);
    s.kind = data;

    to_physical_layer(&s);
    start_timer(frame_nr);
}

/* Protocol 5 */
void protocol5(void)
{
    seq_nr next_frame_to_send;
    seq_nr ack_expected;
    seq_nr frame_expected;
    frame r;
    packet buffer[MAX_SEQ + 1];
    seq_nr nbuffered;
    seq_nr i;
    event_type event;
    
    enable_network_layer();
    ack_expected = 0;
    next_frame_to_send = 0;
    frame_expected = 0;
    nbuffered = 0;

    printf("\n=== PROTOCOL 5 START ===\n\n");

    for (int step = 0; step < 15; step++)  /* Limit number of steps */
    {
        wait_for_event(&event);

        switch (event)
        {
            case network_layer_ready:
                printf(">> Processing network_layer_ready\n");
                from_network_layer(&buffer[next_frame_to_send]);
                nbuffered += 1;
                send_data(next_frame_to_send, frame_expected, buffer);
                inc(next_frame_to_send);
                break;
                
            case frame_arrival:
                printf(">> Processing frame_arrival\n");
                from_physical_layer(&r);
                if (r.seq == frame_expected)
                {
                    to_network_layer(&r.info);
                    inc(frame_expected);
                }
                while (between(ack_expected, r.ack, next_frame_to_send))
                {
                    nbuffered -= 1;
                    stop_timer(ack_expected);
                    inc(ack_expected);
                }
                break;
                
            case cksum_err:
                printf(">> Processing cksum_err - ignoring frame\n");
                break;
                
            case timeout:
                printf(">> Processing timeout - retransmitting\n");
                next_frame_to_send = ack_expected;
                for (i = 1; i <= nbuffered; i++)
                {
                    send_data(next_frame_to_send, frame_expected, buffer);
                    inc(next_frame_to_send);
                }
                break;
                
            default:
                printf(">> Unknown event\n");
                break;
        }
        
        if (nbuffered < MAX_SEQ)
            enable_network_layer();
        else
            disable_network_layer();
            
        printf("State: next_to_send = %d, ack_exp = %d, frame_exp = %d, nbuffered = %d\n\n", next_frame_to_send, ack_expected, frame_expected, nbuffered);
    }
    
    printf("=== PROTOCOL 5 COMPLETED ===\n");
    printf("Total frames sent: %d\n", frame_counter);
}

/* Main function */
int main(void)
{
    protocol5();
    return 0;
}