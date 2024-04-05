import machine
import time

PN532_I2C_ADDRESS = const(0x48 >> 1)
PN532_PREAMBLE = const(0x00)
PN532_STARTCODE1 = const(0x00)
PN532_STARTCODE2 = const(0xFF)
PN532_POSTAMBLE = const(0x00)
PN532_HOSTTOPN532 = const(0xD4)
PN532_PN532TOHOST = const(0xD5)
PN532_ACK_WAIT_TIME = const(5)
PN532_COMMAND_GETFIRMWAREVERSION = const(0x02)
PN532_COMMAND_INDATAEXCHANGE = const(0x40)
PN532_COMMAND_INLISTPASSIVETARGET = const(0x4A)
PN532_MIFARE_ISO14443A = const(0x00) #BrTy 106 kbps ISO14443A
PN532_COMMAND_SAMCONFIGURATION = const(0x14)
PN532_INVALID_ACK = const(-1)
PN532_TIMEOUT = const(-2)
PN532_INVALID_FRAME = const(-3)
PN532_NO_SPACE = const(-4)

PN532_ACK = [0x01, 0x00,0x00,0xFF,0x00,0xFF,0x00] #Including the 0x01 for the RDY bit
PN532_NACK = [0x01, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00] #Including RDY bit
PN532_FRAME_PREAMBLE = [0x01, 0x00, 0x00, 0xFF] #Including RDY bit

PN532_LEN_POS = const(0x04)
PN532_LCS_POS = const(0x05)
PN532_TFI_POS = const(0x06)
PN532_PD0_POS = const(0x07)


command = 0


def writeCommand(header, body=[]):
    global command
    command = header[0]
    total_len = len(header) + len(bytearray(body)) + 1
    checksum = PN532_HOSTTOPN532
    packet = []
    i2c = machine.I2C(0, scl=machine.Pin(9), sda=machine.Pin(8))
    packet.append(PN532_PREAMBLE)
    packet.append(PN532_STARTCODE1)
    packet.append(PN532_STARTCODE2)
    packet.append(total_len)
    packet.append(~total_len + 1)
    packet.append(PN532_HOSTTOPN532)
    for element in header:
        packet.append(element)
        checksum += element
    for element in body:
        packet.append(element)
        checksum += element
    checksum = (~checksum +1) & 0xFF
    packet.append(checksum)
    packet.append(PN532_POSTAMBLE)
    i2c.writeto(PN532_I2C_ADDRESS, bytearray(packet))
    time.sleep_ms(10) #To avoid RAW errors
    return readAckFrame()
    #TODO Anadir la llamada a readACKFrame()

def getResponseLength():
    i2c = machine.I2C(0, scl=machine.Pin(9), sda=machine.Pin(8))
    t1 = time.time()
    while(True):
        frame = list(i2c.readfrom(PN532_I2C_ADDRESS, 5))
        if frame[0] == 0x01:
            break
        if time.time()-t1 >= PN532_ACK_WAIT_TIME:
            return PN532_TIMEOUT
    if frame[0:len(PN532_FRAME_PREAMBLE)] != PN532_FRAME_PREAMBLE:
        return PN532_INVALID_FRAME
    length = frame[-1]
    i2c.writeto(PN532_I2C_ADDRESS, bytearray(PN532_NACK)) #Request another sending of the frame
    time.sleep_ms(10) #To avoid RAW errors
    return length

def read_response(length=6):
    # Leer la respuesta del PN532
    global command
    i2c = machine.I2C(0, scl=machine.Pin(9), sda=machine.Pin(8))
    t1 = time.time()
    length = getResponseLength()
    while(True):
        response = i2c.readfrom(PN532_I2C_ADDRESS, length + 8) #8 due to 6 bytes of header and 2 bytes of postamble
        if response[0] == 0x01:
            break
        if time.time()-t1 >= PN532_ACK_WAIT_TIME:
            return PN532_TIMEOUT
    if list(response[0:len(PN532_FRAME_PREAMBLE)]) != PN532_FRAME_PREAMBLE: #If the preamble is not correct
        return PN532_INVALID_FRAME
    LEN = response[PN532_LEN_POS]
    LCS = response[PN532_LCS_POS]
    TFI = response[PN532_TFI_POS]
    PD = response[PN532_PD0_POS:-2]
    DCS = response[-2]
    POSTAMBLE = response[-1]
    if (LEN + LCS) & 0xFF: #If the lenght and its a2 complement dont match
        return PN532_INVALID_FRAME
    if TFI != PN532_PN532TOHOST: #If the direction is incorrect
        return PN532_INVALID_FRAME
    if PD[0] != command + 1: #The command does not match
        return PN532_INVALID_FRAME
    if sum(PD)+TFI+DCS & 0xFF: #If the DCS does not match
        return PN532_INVALID_FRAME
    if POSTAMBLE != PN532_POSTAMBLE: #If the postamble does not match
        return PN532_INVALID_FRAME
    return PD


def readAckFrame():
    i2c = machine.I2C(0, scl=machine.Pin(9), sda=machine.Pin(8))
    t1 = time.time()
    while(True):
        frame = list(i2c.readfrom(PN532_I2C_ADDRESS, len(PN532_ACK)))
        if frame[0] == 0x01:
            break
        if time.time()-t1 >= PN532_ACK_WAIT_TIME:
            return PN532_TIMEOUT
    return 0 if frame == PN532_ACK else PN532_INVALID_ACK
    
def getFirmwareVersion(print_output=False):
    writeCommand([PN532_COMMAND_GETFIRMWAREVERSION])
    response = read_response()
    if response[0] != PN532_COMMAND_GETFIRMWAREVERSION +1:
        return -1
    IC = response[1]
    Ver = response[2]
    Rev = response[3]
    supp = response[4]
    if print_output:
        print("Detected PN5" + hex(IC)[2:])
        print("FW Version: " + str(Ver) + "." + str(Rev))
    return IC, Ver, Rev, supp

def SAMConfig():
    packet = []
    packet.append(PN532_COMMAND_SAMCONFIGURATION)
    packet.append(0x01) #SAM not used
    packet.append(0x14) #timeout = 1s
    packet.append(0x01) #P70_IRQ pin driven by PN532
    if writeCommand(packet):
        return False
    return 0 < len(read_response())

def read_passive_ID():
    i2c = machine.I2C(0, scl=machine.Pin(9), sda=machine.Pin(8))
    packet = []
    packet.append(PN532_COMMAND_INLISTPASSIVETARGET)
    packet.append(1) # 1 Card (Max 2)
    packet.append(PN532_MIFARE_ISO14443A) #Baudrate MIFARE cards
    if writeCommand(packet):
        return 0
    response = read_response()
    if type(response) is int: #If we have an integer instead of a list, there was a problem (timeout or incorrect frame)
        if response < 0:
            return 0
    if response[0] != PN532_COMMAND_INLISTPASSIVETARGET + 1: #The command does not match
        return 0
    if response[1] != 1: #More than 1 card detected
        return 0
    SENS_RES = response[2] << 8 + response[3]
    ATQA = response[4]
    SAK = response[5]
    length_uid = response[6]
    UID = response[7:7+length_uid] #The UID goes from the 7th byte to the 7 + length
    return list(UID)

def get_str_ID(ID):
    output = str()
    if ID[0] < 0x0F:
        output += "0"
    output += str(hex(ID[0])[2:])
    for i in range(1, len(ID)):
        output += ":"
        if ID[i] < 0xF:
            output += "0"
        output += str(hex(ID[i])[2:])
    return output

def get_int_ID(ID):
    output = 0
    for i in range(0, len(ID)):
        output += (ID[i] << 8*(len(ID)-1-i))
    return output

def get_ID_from_int(ID):
    output = []
    for i in range(0, 7):
        output.append(((ID & (0xFF<<((6-i)*8))) >> (8*(6-i))))
    return output

def demo():   
    getFirmwareVersion(True)   
    SAMConfig()
    UID = read_passive_ID()
    UID_autorizado = [0x01,0x02,0x03,0x04,0x05,0x06,0x07]
    print(UID)
    print(UID_autorizado)
    if UID == UID_autorizado:
        print("Todo bien")
    else:
        print("Tarjeta desconocida")