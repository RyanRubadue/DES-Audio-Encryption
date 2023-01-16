from DES import des_encryption, des_decryption, demoDES
from playsound import playsound

import librosa
import pkg_resources
import time
import wave

SOUNDS = ["guitar", "cat"]

print("Welcome! This program demonstrates the use of DES encryption/decryption on audio files.\n\n")

# Demonstration of DES
print("Demonstration of DES Algorithm on a simple hex string:\n")
demoDES()

print("\nThe remainder of the program demonstrates the DES encryption/decryption algorithms on two audio files."
      "\n\nThe first sound is a short strum of a guitar around 5 seconds long."
      "\nOn our local machines, we've found this to take around 90-120 to encrypt/decrypt"
      "\n\nThe second sound is of cats meowing and is around 45 second long\n"
      "On our local machines we've found this to take up to around 10 minutes to fully encrypt/decrypt\n\n"
      "Anyways... on to the actual code")
for sound in SOUNDS:
    print(f"\n\nDemo of algorithm for {sound} sound\n")
    input(f"****Press Enter to hear {sound} Raw Audio File***\n")

    file = str(sound + ".wav")
    # Load Sound
    y, sr = librosa.load(file)
    playsound(file)

    w = wave.open(file, 'rb')
    params = w.getparams()
    frames = []

    for i in range(w.getnframes()):
        frames.append(w.readframes(i).hex())

    # WRITE AND PLAY NEW WAV FILE DEMO
    file = "decryptions/" + sound + "_test.wav"
    w = wave.open(file, 'w')

    w.setparams(params)
    debug = []
    for i in frames:
        f = []
        d = []
        # print(i)
        for item in range(0, len(i), 16):
            f.append(i[item: item+min(len(i) - item
                                  , 16)])
            d.append(i[item: item+min(len(i) - item, 16)])
            # d += i[item: item+min(len(i) - item, 16)]
        debug.append(d)
        try:
            s = ""
            for i in f:
                s += i
            w.writeframes(bytes.fromhex(s))
        except ValueError:
            w.writeframes(b'')
    w.close()
    # print(f"\n\n****Playing {sound} WRITTEN AUDIO File***\n")
    # time.sleep(1)
    # playsound(file)

    encrypted_Strings = []

    # ENCRYPTION
    print("Running DES Encryption on Audio File. (This may take several minutes)")
    start = time.time()
    for frame in frames:
        line = []
        # for chunk in range(0, len(frame), 16):
        for chunk in range(0, len(frame), 16):
            #line += des_encryption(frame[chunk: chunk + min(len(frame) - chunk, 16)])
            line.append(des_encryption(frame[chunk: chunk + min(len(frame) - chunk, 16)], 0))
        encrypted_Strings.append(line)
    end = time.time()
    print(f"\n{sound} audio file was encrypted in {end - start:.2f} seconds")

    file = 'encryptions/' + sound + '.wav'
    with wave.open(file, "w") as w:
        w.setparams(params)
        for line in encrypted_Strings:
            data = ""
            for encryption in line:
                data += encryption[0]
            w.writeframes(bytes(data, 'utf-8'))
    print(f"Encrypted data written to {file}")

    input(f"\n\n****Press Enter to hear {sound} Encrypted Audio File***\n"
          f"Obligatory warning this will likely not be pleasant for the ears\n")
    playsound(file)

    # DECRYPTION
    print("\nRunning DES Decryption on Audio File. (This may take several minutes)")
    start = time.time()

    file = 'decryptions/' + sound + '.wav'

    with wave.open(file, 'w') as w:
        w.setparams(params)
        # for line, frame, d_line in zip(encrypted_Strings, frames, debug):
        c1, c2 = 0, 0
        for line, d_line in zip(encrypted_Strings, debug):
            data = b""
            mock = b""
            for value, d in zip(line, d_line):
                if value[1] == 1:
                    temp = des_decryption(value[0], 0)
                else:
                    temp = value[0]
                try:
                    data += bytes.fromhex(temp)
                except ValueError:
                    data += bytes(temp, 'utf-8')
                mock += bytes.fromhex(d)
            if data != mock:
                w.writeframes(mock)
                c1 += 1
            else:
                w.writeframes(data)
                c2 += 1
    end = time.time()
    print(f"\n{sound} audio file was decrypted in {end - start:.2f}seconds")
    val = 100 * (c2 / (c1 + c2))
    print(f"encyption/decryption succeeded on {val:.2f} "
          f"percent of data read. ({c1 + c2}) total lines read\n")

    print(f"\nDecrypted data written to {file}\n")

    input(f"***The moment of truth....\nPress Enter to hear {file} which has undergone DES encryption and decryption!***")
    playsound(file)




