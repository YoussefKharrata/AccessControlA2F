package com.accesscontrol;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class AccessControlApplet extends Applet {
    
    // Instructions APDU
    private static final byte INS_SET_PIN = (byte) 0x10;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_STORE_KEY = (byte) 0x30;
    private static final byte INS_GET_KEY = (byte) 0x40;
    private static final byte INS_RESET_TRIES = (byte) 0x50;
    private static final byte INS_GET_USER_ID = (byte) 0x60;
    
    // Constantes
    private static final byte PIN_TRY_LIMIT = (byte) 3;
    private static final byte MAX_PIN_SIZE = (byte) 8;
    private static final short KEY_SIZE = (short) 16; // AES-128
    private static final short USER_ID_SIZE = (short) 16;
    
    // Codes d'erreur personnalisés
    private static final short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    private static final short SW_PIN_TRIES_REMAINING = 0x63C0;
    
    // Stockage
    private OwnerPIN pin;
    private byte[] encryptedKey;
    private byte[] aesKey; 
    private byte[] userId;
    private short userIdLength; // ✅ nouvelle variable
    private AESKey cryptoKey;
    private Cipher cipher;
    private boolean pinVerified;
    
    private AccessControlApplet(byte[] bArray, short bOffset, byte bLength) {
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        
        encryptedKey = new byte[KEY_SIZE];
        aesKey = new byte[KEY_SIZE];
        userId = new byte[USER_ID_SIZE];
        userIdLength = 0;
        
        cryptoKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, 
                                                  KeyBuilder.LENGTH_AES_128, 
                                                  false);
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        
        pinVerified = false;
        
        register();
    }
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new AccessControlApplet(bArray, bOffset, bLength);
    }
    
    public boolean select() {
        pinVerified = false;
        return true;
    }
    
    public void deselect() {
        pin.reset();
        pinVerified = false;
    }
    
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        
        switch (ins) {
            case INS_SET_PIN: setPin(apdu); break;
            case INS_VERIFY_PIN: verifyPin(apdu); break;
            case INS_STORE_KEY: storeEncryptedKey(apdu); break;
            case INS_GET_KEY: getDecryptedKey(apdu); break;
            case INS_RESET_TRIES: resetPinTries(apdu); break;
            case INS_GET_USER_ID: getUserId(apdu); break;
            default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    /**
     * Définir le PIN initial + UserID
     */
    private void setPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        byte pinLength = buffer[ISO7816.OFFSET_CDATA];
        if (pinLength > MAX_PIN_SIZE || pinLength <= 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Mise à jour du PIN
        pin.update(buffer, (short)(ISO7816.OFFSET_CDATA + 1), pinLength);

        // Extraction UserID
        short userIdOffset = (short)(ISO7816.OFFSET_CDATA + 1 + pinLength);
        userIdLength = (short)(bytesRead - 1 - pinLength);

        if (userIdLength > 0 && userIdLength <= USER_ID_SIZE) {
            Util.arrayCopy(buffer, userIdOffset, userId, (short)0, userIdLength);
            Util.arrayFillNonAtomic(userId, userIdLength, (short)(USER_ID_SIZE - userIdLength), (byte)0);
        } else {
            userIdLength = 0;
            Util.arrayFillNonAtomic(userId, (short)0, USER_ID_SIZE, (byte)0);
        }

        // Génération clé AES dérivée du PIN
        deriveAESKey(buffer, (short)(ISO7816.OFFSET_CDATA + 1), pinLength);
    }
    
    private void verifyPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte lc = buffer[ISO7816.OFFSET_LC];
        if (lc > MAX_PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();
        
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, lc)) {
            pinVerified = true;
        } else {
            pinVerified = false;
            byte triesRemaining = pin.getTriesRemaining();
            if (triesRemaining == 0) {
                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
            } else {
                ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | triesRemaining));
            }
        }
    }
    
    private void storeEncryptedKey(APDU apdu) {
        if (!pinVerified) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        if (bytesRead != KEY_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        encryptData(buffer, ISO7816.OFFSET_CDATA, encryptedKey, (short)0, KEY_SIZE);
    }
    
    private void getDecryptedKey(APDU apdu) {
        if (!pinVerified) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        byte[] buffer = apdu.getBuffer();
        decryptData(encryptedKey, (short)0, buffer, (short)0, KEY_SIZE);
        apdu.setOutgoingAndSend((short)0, KEY_SIZE);
    }
    
    private void resetPinTries(APDU apdu) {
        pin.resetAndUnblock();
    }
    
    private void getUserId(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (userIdLength > 0) {
            Util.arrayCopy(userId, (short)0, buffer, (short)0, userIdLength);
            apdu.setOutgoingAndSend((short)0, userIdLength);
        } else {
            apdu.setOutgoingAndSend((short)0, (short)0);
        }
    }
    
    private void deriveAESKey(byte[] pinData, short offset, byte length) {
        Util.arrayFillNonAtomic(aesKey, (short)0, KEY_SIZE, (byte)0);
        if (length <= KEY_SIZE) {
            Util.arrayCopy(pinData, offset, aesKey, (short)0, length);
        } else {
            Util.arrayCopy(pinData, offset, aesKey, (short)0, KEY_SIZE);
        }
        for (short i = 0; i < KEY_SIZE; i++) {
            aesKey[i] = (byte)(aesKey[i] ^ (byte)0xAA);
        }
        cryptoKey.setKey(aesKey, (short)0);
    }
    
    private void encryptData(byte[] input, short inOff, byte[] output, short outOff, short length) {
        byte[] iv = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                     0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
        cipher.init(cryptoKey, Cipher.MODE_ENCRYPT, iv, (short)0, (short)16);
        cipher.doFinal(input, inOff, length, output, outOff);
    }
    
    private void decryptData(byte[] input, short inOff, byte[] output, short outOff, short length) {
        byte[] iv = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                     0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
        cipher.init(cryptoKey, Cipher.MODE_DECRYPT, iv, (short)0, (short)16);
        cipher.doFinal(input, inOff, length, output, outOff);
    }
}
