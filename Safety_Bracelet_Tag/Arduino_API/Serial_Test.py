import time
from Arduino_serial_API import SerialConnection

if __name__ == "__main__":
    connection = SerialConnection(port="COM11", baud_rate=9600)
    connection.init_serial()
    time.sleep(2)  # Optional: wait for Arduino to reset
    connection.send_command("tag1skey3")
    connection.close()