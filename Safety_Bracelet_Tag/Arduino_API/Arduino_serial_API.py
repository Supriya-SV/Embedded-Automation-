import serial
import time

class SerialConnection:
    def __init__(self, port, baud_rate, timeout=1):
        self.port = port
        self.baud_rate = baud_rate
        self.timeout = timeout
        self.ser = None

    def init_serial(self):
        try:
            self.ser = serial.Serial(self.port, self.baud_rate, timeout=self.timeout)
            if self.ser.isOpen():
                print(f"Connected to {self.port}")
            # Wait for Arduino to initialize
            time.sleep(2)
        except serial.SerialException as e:
            print(f"Error opening serial port: {e}")

    def send_command(self, command):
        try:
            if self.ser:
                # Send the command
                self.ser.write(f"{command}\n".encode())  # Encode the string to bytes and send with newline
                print(f"Sent: {command}")
                # Wait for response
                time.sleep(1)  # Wait for response
                if self.ser.in_waiting > 0:
                    response = self.ser.read(self.ser.in_waiting).decode('utf-8').strip()
                    print(f"Arduino: {response}")
        except serial.SerialException as e:
            print(f"Error communicating with Arduino: {e}")

    def close(self):
        if self.ser and self.ser.isOpen():
            self.ser.close()
            print("Serial connection closed.")