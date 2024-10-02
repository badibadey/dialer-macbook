import time
import logging
import random
from threading import Thread
from audiocodes_api import AudioCodesAPI

dialing = False
max_concurrent_calls = 6
current_calls = 0
max_call_duration = 1000000000  # 3 minuty w sekundach
status_check_interval = 15  # Sprawdzaj status co 15 sekund
call_initiation_delay = 2  # Opóźnienie między próbami inicjowania połączeń (w sekundach)

# Inicjalizacja klienta API AudioCodes
api_client = AudioCodesAPI(
    client_id="0K47GcojwESaCOGGKLPAmQ==", 
    secret_key="TbZORBC8P5Jz7Mfz58cXdUi3voK1x8D1", 
    bot="b5568ef4-9eb9-4567-996a-0d261f0ecfd3")
#    bot="06d75663-9190-4ab5-bed4-26de02dd3db4")
def start_dialing(contacts, stats):
    global dialing
    dialing = True
    threads = []

    for contact in contacts:
        while current_calls >= max_concurrent_calls:
            time.sleep(1)  # Czekaj na wolne miejsce

        if not dialing:
            break

        thread = Thread(target=handle_call, args=(contact, stats))
        threads.append(thread)
        thread.start()
        
        # Dodaj losowe opóźnienie między 0.5 a 1.5 sekundy
        time.sleep(call_initiation_delay + random.uniform(-0.5, 0.5))

    for thread in threads:
        thread.join()  # Czekaj na zakończenie wszystkich wątków

def handle_call(contact, stats):
    global current_calls
    current_calls += 1
    contact['status'] = 'Calling'
    contact['time'] = time.strftime('%Y-%m-%d %H:%M:%S')
    contact['reason'] = ''
    logging.info(f"Attempting to start call for {contact['phone']}")
    try:
        conversationId = api_client.start_call(contact['phone'])
        contact['status'] = 'In Progress'
        stats['total_calls'] += 1
        logging.info(f"Call started for {contact['phone']} with conversation ID {conversationId}")
        
        # Delay przed pierwszym sprawdzeniem statusu
        time.sleep(status_check_interval)

        # Start checking the call details
        start_time = time.time()
        while dialing and (time.time() - start_time) < max_call_duration:
            try:
                call_details = api_client.get_call_details(conversationId)
                logging.info(f"Call details for {contact['phone']}: {call_details}")

                if 'durationSeconds' in call_details:
                    contact['duration'] = f"{call_details['durationSeconds']} seconds"
                else:
                    contact['duration'] = 'N/A'
                logging.info(f"Call duration for {contact['phone']}: {contact['duration']}")

                if call_details['machineDetection']:
                    contact['status'] = 'Failed'
                    contact['reason'] = 'Machine Detected'
                    stats['failed_calls'] += 1
                    logging.info(f"Call failed for {contact['phone']}: Machine Detected")
                    break

                if call_details['status'] == 'Completed':
                    if call_details.get('terminationDescription') == 'cancel':
                        contact['status'] = 'Failed'
                        contact['reason'] = 'cancel'
                        stats['failed_calls'] += 1
                    else:
                        contact['status'] = 'Success'
                        contact['reason'] = call_details.get('terminationDescription', 'Unknown')
                        stats['successful_calls'] += 1
                    logging.info(f"Call completed for {contact['phone']}: {contact['status']}")
                    break
                elif call_details['status'] == 'Failed':
                    contact['status'] = 'Failed'
                    contact['reason'] = call_details.get('terminationDescription', 'Unknown')
                    stats['failed_calls'] += 1
                    logging.info(f"Call failed for {contact['phone']}")
                    break
            except Exception as e:
                logging.error(f"Error getting call details for {contact['phone']}: {e}")
            
            # Czekaj przed kolejnym sprawdzeniem statusu
            time.sleep(status_check_interval)
        else:
            contact['status'] = 'Failed'
            contact['reason'] = 'Max duration reached'
            contact['duration'] = f"{max_call_duration} seconds"
            stats['failed_calls'] += 1
            logging.info(f"Call for {contact['phone']} reached max duration")
    except Exception as e:
        logging.error(f"Error during call for {contact['phone']}: {e}")
        contact['status'] = 'Failed'
        contact['reason'] = str(e)
        contact['duration'] = 'N/A'
        stats['failed_calls'] += 1
    finally:
        current_calls -= 1
        time.sleep(2)  # Symulacja opóźnienia między połączeniami

def stop_dialing():
    global dialing
    dialing = False
    logging.info("Dialing stopped")