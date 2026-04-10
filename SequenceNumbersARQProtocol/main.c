/*Протокол 2 (с ожиданием) также обеспечивает только одностороннюю передачу данных,
от отправителя к получателю. Снова предполагается, что в канале связи нет ошибок. Однако
на этот раз емкость буфера получателя ограниченна и, кроме того, ограниченна скорость
обработки данных получателем. Поэтому протокол должен не допускать отправления данных
быстрее, чем получатель способен их обработать.*/

/* Protocol 2 (stop-and-wait) also provides only one-way data transfer,
   from sender to receiver. It is again assumed that there are no errors in the communication channel.
   However, this time the receiver's buffer capacity is limited and, in addition,
   the receiver's data processing speed is limited. Therefore, the protocol must prevent
   sending data faster than the receiver can process it. */

/* main.c - Main program to run Protocol 2 */
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>

/* Forward declarations */
void sender2(void);
void receiver2(void);

/* ========== FUNCTION IMPLEMENTATIONS ========== */

void wait_for_event(event_type *event)
{
    static int call_count = 0;
    *event = frame_arrival;
    printf("wait_for_event: event = frame_arrival (call #%d)\n", ++call_count);
}

void from_network_layer(packet *p)
{
    static int packet_num = 0;
    printf("from_network_layer: got packet %d\n", packet_num);
    for (int i = 0; i < MAX_PKT && i < 10; i++) 
    {
        p->data[i] = (packet_num * 10 + i) % 256;
    }
    packet_num++;
}

void to_network_layer(packet *p)
{
    printf("to_network_layer: delivered packet, first byte = %d\n", p->data[0]);
}

void from_physical_layer(frame *r)
{
    printf("from_physical_layer: received frame\n");
    r->kind = data;
    r->seq = 0;
    r->ack = 0;
    for (int i = 0; i < 10; i++) 
    {
        r->info.data[i] = i;
    }
}

void to_physical_layer(frame *s)
{
    printf("to_physical_layer: sent frame (kind = %d, seq = %u, ack = %u)\n", s->kind, s->seq, s->ack);
}

void start_timer(seq_nr k)
{
    printf("start_timer: started timer for seq %u\n", k);
}

void stop_timer(seq_nr k)
{
    printf("stop_timer: stopped timer for seq %u\n", k);
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
    printf("enable_network_layer: network layer enabled\n");
}

void disable_network_layer(void)
{
    printf("disable_network_layer: network layer disabled\n");
}

/* ========== PROTOCOL 2 (STOP-AND-WAIT) ========== */

void sender2(void)
{
    frame s;                            /* buffer for outgoing frame */
    packet buffer;                      /* buffer for outgoing packet */
    event_type event;                   /* frame_arrival is the only possible event */
    int packets_sent = 0;
    const int MAX_PACKETS = 3;

    printf("\n=== SENDER (sender2) started ===\n");
    
    while (packets_sent < MAX_PACKETS)
    {
        printf("\n[Sender] Loop #%d\n", packets_sent + 1);
        
        from_network_layer(&buffer);    /* get packet from network layer for transmission */
        s.info = buffer;                /* copy it into frame s for transmission */
        s.kind = data;                  /* frame type - data */
        s.seq = packets_sent;           /* set sequence number */
        s.ack = 0;                      /* acknowledgment not used */
        
        printf("[Sender] Sending data frame (seq = %u)\n", s.seq);
        to_physical_layer(&s);          /* send frame */
        
        printf("[Sender] Waiting for acknowledgment...\n");
        wait_for_event(&event);         /* do not continue until permission is received */
        
        packets_sent++;
    }
    
    printf("\n[Sender] Finished sending %d packets\n", MAX_PACKETS);
}

void receiver2(void)
{
    frame r, s;                         /* buffer for frames */
    event_type event;                   /* frame_arrival is the only possible event */
    int packets_received = 0;
    const int MAX_PACKETS = 3;

    printf("\n=== RECEIVER (receiver2) started ===\n");
    
    while (packets_received < MAX_PACKETS)
    {
        printf("\n[Receiver] Loop #%d\n", packets_received + 1);
        
        printf("[Receiver] Waiting for frame...\n");
        wait_for_event(&event);         /* the only possibility - frame arrival */
        
        from_physical_layer(&r);        /* get incoming frame */
        printf("[Receiver] Received data frame\n");
        
        to_network_layer(&r.info);      /* pass data to network layer */
        
        /* Send an empty frame (acknowledgment) to wake up the sender */
        s.kind = ack;                   /* frame type - acknowledgment */
        s.seq = packets_received;       /* sequence number of received packet */
        s.ack = packets_received;       /* acknowledgment number */
        
        printf("[Receiver] Sending acknowledgment (ack = %u)\n", s.ack);
        to_physical_layer(&s);          /* send empty frame to "wake up" the sender */
        
        packets_received++;
    }
    
    printf("\n[Receiver] Received and acknowledged %d packets\n", MAX_PACKETS);
}

/* ========== MAIN FUNCTION ========== */

int main(void)
{
    printf("========================================\n");
    printf("PROTOCOL 2: ONE-WAY STOP-AND-WAIT TRANSMISSION\n");
    printf("========================================\n");
    printf("Description: The protocol provides flow control,\n");
    printf("preventing data from being sent faster than the receiver\n");
    printf("can process it.\n");
    printf("========================================\n\n");
    
    printf("PROTOCOL SIMULATION:\n\n");
    
    printf(">>> STARTING SENDER:\n");
    sender2();
    
    printf("\n>>> STARTING RECEIVER:\n");
    receiver2();
    
    printf("\n========================================\n");
    printf("SIMULATION COMPLETE\n");
    printf("========================================\n");
    
    return 0;
}