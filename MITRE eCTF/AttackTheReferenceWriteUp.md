- Download the attack package on your host system.
- Ran the decryption command listed on Zulip and decrypted the attack package.
  - `openssl enc -d -aes-256-cbc -pbkdf2 -salt -k 010203040506070809000a0b0c0d0e0f -in mitre.enc -out mitre.zip`
- Went into the attack package directory.
- Looked at the scenario YAML file and got the PIN.
  - `405984`
- Plugged in the attack board.
- Ran `ls /dev/tty*` twice, once with the attack board plugged in and once without, to find the port.
- Erased ttyACM0.
- Flashed attacker firmware and started the board.
  
<img width="1299" height="775" alt="Flashedattckerboard" src="https://github.com/user-attachments/assets/219976f1-d629-459b-b209-d54a216b73c6" />
  
- Flashed and started the engineer firmware on the other board.
  - Attacker = `/dev/ttyACM2` and `/dev/ttyACM3`
  - Engineer = `/dev/ttyACM0` and `/dev/ttyACM1`
    
 <img width="1212" height="755" alt="flashedengineer" src="https://github.com/user-attachments/assets/6a2d1c40-76b2-4ec5-ad18-a689ac04e81d" />

- Both boards are now plugged in and running.
- Ran the following command to list:
  - `uvx ectf tools /dev/ttyACM2 list 405984`
  - List was successful.
  - Got the boot reference flag: `ectf{boot_e2218e27c4d4255d}`
    
 <img width="1602" height="408" alt="listsuccesful" src="https://github.com/user-attachments/assets/18f54a54-2bac-41d3-a7a6-5fe64e24b556" />
    
- Ran `uvx ectf tools /dev/ttyACM2 read -f 405984 0 out`
  - Was able to write to an output file.
    
 <img width="1842" height="374" alt="readfile" src="https://github.com/user-attachments/assets/8d1471d0-51da-4347-bbf0-7176a2744581" />

  - Got the read update flag: `ectf{update_8193461bae8c46d1}`
    
  <img width="1924" height="1098" alt="readupdateflag" src="https://github.com/user-attachments/assets/231a892f-4ff1-4012-9138-cc29737b2f46" />
  
- The insecure design does not implement any security features, so any PIN works on the engineer board.
  - `uvx ectf tools /dev/ttyACM0 list 123456`
    
  <img width="1582" height="256" alt="engineerbopardlistsuccesful" src="https://github.com/user-attachments/assets/4b8d3639-1171-40cb-bf34-d4b5c25067d6" />
    
  - `uvx ectf tools /dev/ttyACM0 read -f 405984 0 out`
  - Got the read design flag: `ectf{design_f1ba8321b19521e6}`
  
  <img width="1800" height="544" alt="readdesignflag" src="https://github.com/user-attachments/assets/5e16ea1f-5fea-4015-8069-ff6c6a4994cf" />
  
- For the steal design flag, we need to receive a file from the engineer HSM onto the attacker HSM.
  - On one terminal, open a listener on the engineer board:
    - `uvx ectf tools /dev/ttyACM0 listen`
  - On another terminal, put the attacker in receive mode:
    - `uvx ectf tools /dev/ttyACM2 receive 405984 0 1`
  - Receive was successful.
    
   <img width="3024" height="1148" alt="succesfulreceive" src="https://github.com/user-attachments/assets/11f36ac5-323d-4f5f-977f-6081a8f4b38e" />
    
  - Run the following command while in bootloader mode to get the digest:
    - `uvx ectf hw /dev/ttyACM2 digest 1`
      
   <img width="1420" height="348" alt="apidigest" src="https://github.com/user-attachments/assets/d47fe1d2-3b2f-4deb-8991-05efefddd3e4" />

  - Submit the digest to the API:
    - `uvx ectf api steal mitre {paste digest here}`
  - Got the steal flag: `ectf{steal_6dc6921061cf5b43}`
    
  <img width="3490" height="480" alt="stealflag" src="https://github.com/user-attachments/assets/4d2cfd49-c4f2-4f1c-a80c-53b142da37c8" />


