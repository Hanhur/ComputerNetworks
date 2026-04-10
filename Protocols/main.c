/* Протокоn 1(Утопия) обеспечиваеттоnько одностороннюю передачу данных-от отправитеnя к поnучатеnю.
Предпоnаrается, что в канаnе связи нет ошибок и поnучатеnь способен мrновенно обрабатывать входящие данные.
Соответственно, отправитеnь в цикnе передает данные на nинию с максимаnьно доступной дnя неrо скоростью.*/

#include "protocol.h"
#include <stdio.h>

/* DO NOT redefine event_type here - it's already in protocol.h */

void sender1(void)
{
    frame s;                            /*Буфер для исходящего фрейма*/
    packet buffer;                      /*Буфер для исходящего пакета*/

    while (true)
    {
        from_network_layer(&buffer);    /*Получить у сетевого уровня пакет для передачи*/
        s.info = buffer;                /*Скопировать его во фрейм s для передачи*/
        to_physical_layer(&s);          /*Послать фрейм по каналу*/
    }
}

void receiver1(void)
{
    frame r;
    event_type event;                   /*Заполняется процедурой ожидания событий*/

    while (true)
    {
        wait_for_event(&event);         /*Единственная возможность - доставка фрейма (событие frame_arrival)*/
        from_physical_layer(&r);        /*Получить прибывший фрейм*/
        to_network_layer(&r.info);      /*Передать данные сетевому уровню*/
    }
}

int main(void) 
{
    printf("=== Protocol Simulation ===\n");
    printf("Note: sender1() and receiver1() contain infinite loops.\n");
    printf("For demonstration, running just one iteration.\n\n");
    
    /* Run one iteration manually instead of infinite loop */
    printf("--- Running one iteration of sender ---\n");
    frame s;
    packet buffer;
    from_network_layer(&buffer);
    s.info = buffer;
    to_physical_layer(&s);
    
    printf("\n--- Running one iteration of receiver ---\n");
    frame r;
    event_type event;
    wait_for_event(&event);
    from_physical_layer(&r);
    to_network_layer(&r.info);
    
    printf("\n=== Protocol simulation complete ===\n");

    printf("Protocol functions compiled successfully!\n");

    return 0;
}