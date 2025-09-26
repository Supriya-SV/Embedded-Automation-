import pyvisa

class PowerSupply:
    def __init__(self, port):
        self.rm = pyvisa.ResourceManager()
        self.psu = self.rm.open_resource(port)

    def get_info(self):
        query = self.psu.query("*IDN?")
        return print(f"Power suppy info: {query.strip()}")

    def set_voltage(self, voltage):
        self.psu.write(f"VSET1:{voltage}")
        print(f"Voltage set to {voltage}V")

    def set_current(self, current):
        self.psu.write(f"ISET1:{current}")
        print(f"Current set to {current}A")

    def get_voltage(self):
        voltage = self.psu.query("VSET1?")
        return print(f"Set Voltage: {voltage.strip()}V")

    def get_current(self):
        current = self.psu.query("ISET1?")
        return print(f"Set Current: {current.strip()}A")

    def turn_on(self):
        self.psu.write("OUT1")
        print("Power supply turned ON")

    def turn_off(self):
        self.psu.write("OUT0")
        print("Power supply turned OFF")

    def close(self):
        self.psu.close()
        print("Connection closed")
