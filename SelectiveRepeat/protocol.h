#define MAX_PKT 1024                                    /*Определяет пакет в байтах*/
#define inc(k) if (k < MAX_SEQ) k = k + 1; else k = 0   /*Макрос inc развертывается прямо в строке: циклически увеличить переменную k.*/

/* Define MAX_SEQ if not already defined */
#ifndef MAX_SEQ
#define MAX_SEQ 7
#endif

typedef enum {false, true} boolean;                     /*Тип boolean*/
typedef unsigned int seq_nr;                            /*Порядковый номер фреймов или подтверждений*/
typedef struct {unsigned char data[MAX_PKT];} packet;   /*Определение пакета*/
typedef enum {data, ack, nak} frame_kind;               /*Определение типа фрейма*/

/* Definition of event_type - MUST be before any function that uses it */
typedef enum {
    frame_arrival,
    cksum_err, 
    timeout, 
    ack_timeout, 
    network_layer_ready
} event_type;

typedef struct                                          /*Фреймы, транспортируемые на данном уровне*/
{
    frame_kind kind;                                    /*Тип фрейма*/
    seq_nr seq;                                         /*Порядковый номер*/
    seq_nr ack;                                         /*Номер подтверждения*/
    packet info;                                       /*Пакет сетевого уровня*/
} frame;

/*Ожидание события и вернуть тип события в переменной event.*/
void wait_for_event(event_type *event);

/*Получить пакет у сетевого уровня для передачи по каналу.*/
void from_network_layer(packet *p);

/*Передать информацию из полученного пакета сетевому уровню.*/
void to_network_layer(packet *p);

/*Получить пришедший пакет у физического уровня и скопировать его в r.*/
void from_physical_layer(frame *r);

/*Передать фрейм физическому уровню для отправки.*/
void to_physical_layer(frame *s);

/*Запустить таймер и разрешить событие timeout.*/
void start_timer(seq_nr k);

/*Запустить таймер и запретить событие timeout.*/
void stop_timer(seq_nr k);

/*Запустить вспомогательный таймер и разрешить событие ack_timeout.*/
void start_ack_timer(void);

/*Запустить вспомогательный таймер и запретить событие ack_timeout.*/
void stop_ack_timer(void);

/*Разрешить сетевому уровню инициировать событие network_layer_ready.*/
void enable_network_layer(void);

/*Запретить сетевому уровню инициировать событие network_layer_ready.*/
void disable_network_layer(void);