import threading
from threading import BoundedSemaphore

max_connections = 2
connection_lock = BoundedSemaphore(value=max_connections)


# class PrintSomeNumbers(Thread):
#
#     def __init__(self, start_number):
#         Thread.__init__(self)
#         self.start_number = start_number
#         connection_lock.acquire()

def print_some_numbers(start_number):
    connection_lock.acquire()
    x = start_number
    for i in range(1, 10):
        x += 1
        print start_number, x
    connection_lock.release()

threads = []

for i in range(1, 5):
    start_number = i
    t = threading.Thread(target=print_some_numbers, args=(start_number,))
    threads.append(t)

for thread in threads:
    thread.start()
    thread.join()
