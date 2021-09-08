#!/usr/bin/python
import wave, os, struct

os.chdir("./finals/walk/_stego.png.extracted")

wav= wave.open("music.wav", mode='rb')
print (wav.getparams())


frame_bytes = bytearray(list(wav.readframes(wav.getnframes())))
shorts = struct.unpack('H'*(len(frame_bytes)//2), frame_bytes)
    
# Get all LSB's
extractedLSB = ""
for i in range(0, len(shorts)):
        extractedLSB += str(shorts[i] & 1 )# divide strings into blocks of eight binary strings
# convert them and join them back to string
string_blocks = (extractedLSB[i:i+8] for i in range(0, len(extractedLSB), 8))
decoded = ''.join(chr(int(char, 2)) for char in string_blocks)
print(decoded[:500])


extracted_left = shorts[::2] 
extracted_right = shorts[1::2]
extractedLSB = ""
for i in range(0, len(extracted_left)):
    extractedLSB += (str(extracted_left[i] & 1)) if i%2==0 else (str(extracted_right[i] & 1))
    
string_blocks = (extractedLSB[i:i+8] for i in range(0, len(extractedLSB), 8))
decoded = ''.join(chr(int(char, 2)) for char in string_blocks)

print(decoded[0:200].encode('utf-8'))

wav.close()