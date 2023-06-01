package org.example.aesalgorithm;



import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Arrays;

public class AES {
    private byte[] data;
    private byte[] key;
    private int opmode;
    private byte[] encrypt;
    private byte[] decript;
    public static final int ENCRYPT_MODE = 1;
    public static final int DECRYPT_MODE = 2;

    private final int BLOCK_SIZE = 16;
    private final int Nr = 10; // количество шагов для 128 битного ключа
    private final int Nb =4; // число столбцов
    private final int Nk = 4;
    private byte[][] keyShedule = new byte[4*(Nb+1)][Nb];
    private final byte[][] sBox = {
            {(byte) 0x63, (byte) 0x7C, (byte) 0x77, (byte) 0x7B, (byte) 0xF2, (byte) 0x6B, (byte) 0x6F, (byte) 0xC5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2B, (byte) 0xFE, (byte) 0xD7, (byte) 0xAB, (byte) 0x76},
            {(byte) 0xCA, (byte) 0x82, (byte) 0xC9, (byte) 0x7D, (byte) 0xFA, (byte) 0x59, (byte) 0x47, (byte) 0xF0, (byte) 0xAD, (byte) 0xD4, (byte) 0xA2, (byte) 0xAF, (byte) 0x9C, (byte) 0xA4, (byte) 0x72, (byte) 0xC0},
            {(byte) 0xB7, (byte) 0xFD, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3F, (byte) 0xF7, (byte) 0xCC, (byte) 0x34, (byte) 0xA5, (byte) 0xE5, (byte) 0xF1, (byte) 0x71, (byte) 0xD8, (byte) 0x31, (byte) 0x15},
            {(byte) 0x04, (byte) 0xC7, (byte) 0x23, (byte) 0xC3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9A, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xE2, (byte) 0xEB, (byte) 0x27, (byte) 0xB2, (byte) 0x75},
            {(byte) 0x09, (byte) 0x83, (byte) 0x2C, (byte) 0x1A, (byte) 0x1B, (byte) 0x6E, (byte) 0x5A, (byte) 0xA0, (byte) 0x52, (byte) 0x3B, (byte) 0xD6, (byte) 0xB3, (byte) 0x29, (byte) 0xE3, (byte) 0x2F, (byte) 0x84},
            {(byte) 0x53, (byte) 0xD1, (byte) 0x00, (byte) 0xED, (byte) 0x20, (byte) 0xFC, (byte) 0xB1, (byte) 0x5B, (byte) 0x6A, (byte) 0xCB, (byte) 0xBE, (byte) 0x39, (byte) 0x4A, (byte) 0x4C, (byte) 0x58, (byte) 0xCF},
            {(byte) 0xD0, (byte) 0xEF, (byte) 0xAA, (byte) 0xFB, (byte) 0x43, (byte) 0x4D, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xF9, (byte) 0x02, (byte) 0x7F, (byte) 0x50, (byte) 0x3C, (byte) 0x9F, (byte) 0xA8},
            {(byte) 0x51, (byte) 0xA3, (byte) 0x40, (byte) 0x8F, (byte) 0x92, (byte) 0x9D, (byte) 0x38, (byte) 0xF5, (byte) 0xBC, (byte) 0xB6, (byte) 0xDA, (byte) 0x21, (byte) 0x10, (byte) 0xFF, (byte) 0xF3, (byte) 0xD2},
            {(byte) 0xCD, (byte) 0x0C, (byte) 0x13, (byte) 0xEC, (byte) 0x5F, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xC4, (byte) 0xA7, (byte) 0x7E, (byte) 0x3D, (byte) 0x64, (byte) 0x5D, (byte) 0x19, (byte) 0x73},
            {(byte) 0x60, (byte) 0x81, (byte) 0x4F, (byte) 0xDC, (byte) 0x22, (byte) 0x2A, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xEE, (byte) 0xB8, (byte) 0x14, (byte) 0xDE, (byte) 0x5E, (byte) 0x0B, (byte) 0xDB},
            {(byte) 0xE0, (byte) 0x32, (byte) 0x3A, (byte) 0x0A, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5C, (byte) 0xC2, (byte) 0xD3, (byte) 0xAC, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xE4, (byte) 0x79},
            {(byte) 0xE7, (byte) 0xC8, (byte) 0x37, (byte) 0x6D, (byte) 0x8D, (byte) 0xD5, (byte) 0x4E, (byte) 0xA9, (byte) 0x6C, (byte) 0x56, (byte) 0xF4, (byte) 0xEA, (byte) 0x65, (byte) 0x7A, (byte) 0xAE, (byte) 0x08},
            {(byte) 0xBA, (byte) 0x78, (byte) 0x25, (byte) 0x2E, (byte) 0x1C, (byte) 0xA6, (byte) 0xB4, (byte) 0xC6, (byte) 0xE8, (byte) 0xDD, (byte) 0x74, (byte) 0x1F, (byte) 0x4B, (byte) 0xBD, (byte) 0x8B, (byte) 0x8A},
            {(byte) 0x70, (byte) 0x3E, (byte) 0xB5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xF6, (byte) 0x0E, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xB9, (byte) 0x86, (byte) 0xC1, (byte) 0x1D, (byte) 0x9E},
            {(byte) 0xE1, (byte) 0xF8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xD9, (byte) 0x8E, (byte) 0x94, (byte) 0x9B, (byte) 0x1E, (byte) 0x87, (byte) 0xE9, (byte) 0xCE, (byte) 0x55, (byte) 0x28, (byte) 0xDF},
            {(byte) 0x8C, (byte) 0xA1, (byte) 0x89, (byte) 0x0D, (byte) 0xBF, (byte) 0xE6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2D, (byte) 0x0F, (byte) 0xB0, (byte) 0x54, (byte) 0xBB, (byte) 0x16}
    };
    private final byte[][] invSBox = {
            {(byte) 0x52, (byte) 0x09, (byte) 0x6A, (byte) 0xD5, (byte) 0x30, (byte) 0x36, (byte) 0xA5, (byte) 0x38, (byte) 0xBF, (byte) 0x40, (byte) 0xA3, (byte) 0x9E, (byte) 0x81, (byte) 0xF3, (byte) 0xD7, (byte) 0xFB},
            {(byte) 0x7C, (byte) 0xE3, (byte) 0x39, (byte) 0x82, (byte) 0x9B, (byte) 0x2F, (byte) 0xFF, (byte) 0x87, (byte) 0x34, (byte) 0x8E, (byte) 0x43, (byte) 0x44, (byte) 0xC4, (byte) 0xDE, (byte) 0xE9, (byte) 0xCB},
            {(byte) 0x54, (byte) 0x7B, (byte) 0x94, (byte) 0x32, (byte) 0xA6, (byte) 0xC2, (byte) 0x23, (byte) 0x3D, (byte) 0xEE, (byte) 0x4C, (byte) 0x95, (byte) 0x0B, (byte) 0x42, (byte) 0xFA, (byte) 0xC3, (byte) 0x4E},
            {(byte) 0x08, (byte) 0x2E, (byte) 0xA1, (byte) 0x66, (byte) 0x28, (byte) 0xD9, (byte) 0x24, (byte) 0xB2, (byte) 0x76, (byte) 0x5B, (byte) 0xA2, (byte) 0x49, (byte) 0x6D, (byte) 0x8B, (byte) 0xD1, (byte) 0x25},
            {(byte) 0x72, (byte) 0xF8, (byte) 0xF6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xD4, (byte) 0xA4, (byte) 0x5C, (byte) 0xCC, (byte) 0x5D, (byte) 0x65, (byte) 0xB6, (byte) 0x92},
            {(byte) 0x6C, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xFD, (byte) 0xED, (byte) 0xB9, (byte) 0xDA, (byte) 0x5E, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xA7, (byte) 0x8D, (byte) 0x9D, (byte) 0x84},
            {(byte) 0x90, (byte) 0xD8, (byte) 0xAB, (byte) 0x00, (byte) 0x8C, (byte) 0xBC, (byte) 0xD3, (byte) 0x0A, (byte) 0xF7, (byte) 0xE4, (byte) 0x58, (byte) 0x05, (byte) 0xB8, (byte) 0xB3, (byte) 0x45, (byte) 0x06},
            {(byte) 0xD0, (byte) 0x2C, (byte) 0x1E, (byte) 0x8F, (byte) 0xCA, (byte) 0x3F, (byte) 0x0F, (byte) 0x02, (byte) 0xC1, (byte) 0xAF, (byte) 0xBD, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8A, (byte) 0x6B},
            {(byte) 0x3A, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4F, (byte) 0x67, (byte) 0xDC, (byte) 0xEA, (byte) 0x97, (byte) 0xF2, (byte) 0xCF, (byte) 0xCE, (byte) 0xF0, (byte) 0xB4, (byte) 0xE6, (byte) 0x73},
            {(byte) 0x96, (byte) 0xAC, (byte) 0x74, (byte) 0x22, (byte) 0xE7, (byte) 0xAD, (byte) 0x35, (byte) 0x85, (byte) 0xE2, (byte) 0xF9, (byte) 0x37, (byte) 0xE8, (byte) 0x1C, (byte) 0x75, (byte) 0xDF, (byte) 0x6E},
            {(byte) 0x47, (byte) 0xF1, (byte) 0x1A, (byte) 0x71, (byte) 0x1D, (byte) 0x29, (byte) 0xC5, (byte) 0x89, (byte) 0x6F, (byte) 0xB7, (byte) 0x62, (byte) 0x0E, (byte) 0xAA, (byte) 0x18, (byte) 0xBE, (byte) 0x1B},
            {(byte) 0xFC, (byte) 0x56, (byte) 0x3E, (byte) 0x4B, (byte) 0xC6, (byte) 0xD2, (byte) 0x79, (byte) 0x20, (byte) 0x9A, (byte) 0xDB, (byte) 0xC0, (byte) 0xFE, (byte) 0x78, (byte) 0xCD, (byte) 0x5A, (byte) 0xF4},
            {(byte) 0x1F, (byte) 0xDD, (byte) 0xA8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xC7, (byte) 0x31, (byte) 0xB1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xEC, (byte) 0x5F},
            {(byte) 0x60, (byte) 0x51, (byte) 0x7F, (byte) 0xA9, (byte) 0x19, (byte) 0xB5, (byte) 0x4A, (byte) 0x0D, (byte) 0x2D, (byte) 0xE5, (byte) 0x7A, (byte) 0x9F, (byte) 0x93, (byte) 0xC9, (byte) 0x9C, (byte) 0xEF},
            {(byte) 0xA0, (byte) 0xE0, (byte) 0x3B, (byte) 0x4D, (byte) 0xAE, (byte) 0x2A, (byte) 0xF5, (byte) 0xB0, (byte) 0xC8, (byte) 0xEB, (byte) 0xBB, (byte) 0x3C, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61},
            {(byte) 0x17, (byte) 0x2B, (byte) 0x04, (byte) 0x7E, (byte) 0xBA, (byte) 0x77, (byte) 0xD6, (byte) 0x26, (byte) 0xE1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0C, (byte) 0x7D}
    };
    private final byte[][] rcon = {
            {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80, (byte) 0x1B, (byte) 0x36},
            {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00},
            {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00},
            {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00}
    };
    public AES(byte[] input,byte[] key,int opmode) throws Exception {
        if(key == null){
            throw new Exception("Key is null");
        }
        if(key.length == 0){
            throw new Exception("Key is empty");
        }
        if(key.length<16){
            throw new Exception("Key is bad");
        }
        if(input == null){
            throw new Exception("Data is null");
        }
        if(input.length == 0){
            throw new Exception("Data is empty");
        }
        if(opmode != 1 && opmode !=2){
            throw new Exception("Bad opmode");
        }
        this.data = data;
        this.key = key;
        this.opmode = opmode;
        if(opmode==1){
            this.encrypt = getEncrypt(input,key);
        }else if(opmode ==2){
            this.decript = getDecrypt(input,key);
        }
    }
    private byte[] getEncrypt(byte[] input, byte[] key) {
        byte[][] state = new byte[4][Nb];
        // Инициализация состояния
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = (byte) (input[4*i+j] & 0xFF);
            }
        }
        System.out.println("En first");
        Sout(state);
        // Расширение ключа
        byte[][] expandedKey = keyExpansion(key);

        // Инициализация раундового ключа
        byte[][] roundKey = getRoundKey(expandedKey, 0);

        // Начальный раунд
        addRoundKey(state, roundKey);

        // Основные раунды
        for (int round = 1; round <= Nr - 1; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            roundKey = getRoundKey(expandedKey, round);
            addRoundKey(state, roundKey);

        }

        // Последний раунд без операции mixColumns
        subBytes(state);
        shiftRows(state);
        roundKey = getRoundKey(expandedKey, Nr);
        addRoundKey(state, roundKey);
        // Конвертация состояния в одномерный массив байтов
        byte[] output = new byte[Nb * 4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                output[i * 4 + j] = state[i][j];
            }
        }
        System.out.println("En sec");
        Sout(state);
        return output;
    }

    private byte[] getDecrypt(byte[] input, byte[] key) {
        byte[][] state = new byte[4][Nb];
        // Инициализация состояния
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = (byte) (input[i*Nb + j] & 0xFF);
            }
        }
        System.out.println("Dec first");
        Sout(state);
        // Расширение ключа
        byte[][] expandedKey = keyExpansion(key);

        // Инициализация раундового ключа
        byte[][] roundKey = getRoundKey(expandedKey, Nr);

        // Последний раунд без операции mixColumns
        addRoundKey(state, roundKey);


        // Основные раунды
        for (int round = Nr - 1; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            roundKey = getRoundKey(expandedKey, round);
            addRoundKey(state, roundKey);
            invMixColumns(state);
        }

        // Начальный раунд
        invShiftRows(state);
        invSubBytes(state);
        roundKey = getRoundKey(expandedKey, 0);
        addRoundKey(state, roundKey);


        // Конвертация состояния в одномерный массив байтов
        byte[] output = new byte[Nb * 4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                output[i *Nb+ j] = state[i][j];
            }
        }
        System.out.println("Dec sec");
        Sout(state);
        return output;
    }

    private void subBytes(byte[][] input){
        for(int i =0;i<4;i++){
            for (int j = 0;j<Nb;j++){
                int rowIndex = (input[i][j] & 0xFF) >>> 4; // получение индекса строки
                int colIndex = input[i][j] & 0x0F; // получение индекса столбца
                input[i][j] = (byte) sBox[rowIndex][colIndex];
            }
        }
    }
    private void invSubBytes(byte[][] input) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                int rowIndex = (input[i][j] & 0xFF) >>> 4; // получение индекса строки
                int colIndex = input[i][j] & 0x0F; // получение индекса столбца
                input[i][j] = (byte) invSBox[rowIndex][colIndex];
            }
        }
    }

    private void shiftRows(byte[][] input) {
        int numRows = input.length;

        for (int row = 0; row < numRows; row++) {
            int shiftAmount = row;
            byte[] shiftedRow = new byte[Nb];
            for (int col = 0; col < Nb; col++) {
                int newCol = (col - shiftAmount + Nb) % Nb;
                shiftedRow[newCol] = input[row][col];
            }
            input[row] = shiftedRow;
        }
    }
    private void invShiftRows(byte[][] input) {
        int numRows = input.length;

        for (int row = 0; row < numRows; row++) {
            int shiftAmount = row;
            byte[] shiftedRow = new byte[Nb];
            for (int col = 0; col < Nb; col++) {
                int newCol = (col + shiftAmount) % Nb;
                shiftedRow[newCol] = input[row][col];
            }
            input[row] = shiftedRow;
        }
    }

    private void Sout(byte[][] matrix) {
        int rows = matrix.length;
        int columns = matrix[0].length;

        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < columns; j++) {
                int value = matrix[i][j] & 0xFF;
                System.out.printf("%02X ", value); // Выводим значение в шестнадцатеричном формате
            }
            System.out.println(); // Переход на новую строку после каждой строки матрицы
        }
    }
    private void mixColumns(byte[][] state) {
        int[] temp = new int[4];
        for (int i = 0; i < Nb; i++) {
            temp[0] = multiply(state[0][i], (byte) 0x02) ^ multiply(state[1][i], (byte) 0x03) ^ state[2][i] ^ state[3][i];
            temp[1] = state[0][i] ^ multiply(state[1][i], (byte) 0x02) ^ multiply(state[2][i], (byte) 0x03) ^ state[3][i];
            temp[2] = state[0][i] ^ state[1][i] ^ multiply(state[2][i], (byte) 0x02) ^ multiply(state[3][i], (byte) 0x03);
            temp[3] = multiply(state[0][i], (byte) 0x03) ^ state[1][i] ^ state[2][i] ^ multiply(state[3][i], (byte) 0x02);

            for (int j = 0; j < Nb; j++) {
                state[j][i] = (byte) temp[j];
            }
        }
    }

    private void invMixColumns(byte[][] state) {
        int[] temp = new int[4];
        for (int i = 0; i < Nb; i++) {
            temp[0] = multiply(state[0][i], (byte) 0x0E) ^ multiply(state[1][i], (byte) 0x0B) ^ multiply(state[2][i], (byte) 0x0D) ^ multiply(state[3][i], (byte) 0x09);
            temp[1] = multiply(state[0][i], (byte) 0x09) ^ multiply(state[1][i], (byte) 0x0E) ^ multiply(state[2][i], (byte) 0x0B) ^ multiply(state[3][i], (byte) 0x0D);
            temp[2] = multiply(state[0][i], (byte) 0x0D) ^ multiply(state[1][i], (byte) 0x09) ^ multiply(state[2][i], (byte) 0x0E) ^ multiply(state[3][i], (byte) 0x0B);
            temp[3] = multiply(state[0][i], (byte) 0x0B) ^ multiply(state[1][i], (byte) 0x0D) ^ multiply(state[2][i], (byte) 0x09) ^ multiply(state[3][i], (byte) 0x0E);

            for (int j = 0; j < Nb; j++) {
                state[j][i] = (byte) temp[j];
            }
        }
    }

    private byte multiply(byte a, byte b) {
        int result = 0;
        int temp;
        int unsignedA = a & 0xFF; // Преобразование a в беззнаковое значение

        while (unsignedA != 0) {
            if ((unsignedA & 1) != 0) {
                result ^= b;
            }
            temp = b & 0x80;
            b <<= 1;
            if (temp != 0) {
                b ^= 0x1b;
            }
            unsignedA >>= 1;
        }

        return (byte) result;
    }

    private byte[] getColumnFromMatrix(byte[][] matrix,int a){
        byte[] result = new byte[Nb];
        for(int i = a-1,j=0;j<Nb;j++){
            result[j] = matrix[j][i];
        }
        return result;
    }
    private byte[][] keyExpansion(byte[] key) {
        byte[][] w = new byte[4][Nb * (Nr + 1)];
        byte[] temp = new byte[4];

        for (int i = 0; i < Nk; i++) {
            int index = i * 4;
            byte[] range = Arrays.copyOfRange(key, index, index + 4);
            System.arraycopy(range, 0, w[i], 0, range.length);
        }
        for (int i = Nk; i < Nb * (Nr + 1); i++) {

            temp = getColumnFromMatrix(w,i);

            if (i % Nk == 0) {
                temp = subWord(rotateWord(temp));
                byte[] rconValue = getColumnByte(rcon,i/Nk);
                for (int j = 0; j < 4; j++) {
                    temp[j] ^= rconValue[j];
                }
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp);
            }

            for (int j = 0; j < 4; j++) {
                w[j][i] = (byte) (w[j][i-Nk]^ temp[j]);
            }

        }
        return w;
    }

    private byte[] subWord(byte[] word) {
        byte[] result = new byte[word.length];
        for (int i = 0; i < word.length; i++) {
            result[i] = sBox[(word[i] & 0xFF) >>> 4][word[i] & 0x0F];
        }
        return result;
    }

    private byte[] rotateWord(byte[] word) {
        byte[] result = new byte[word.length];
        result[0] = word[1];
        result[1] = word[2];
        result[2] = word[3];
        result[3] = word[0];
        return result;
    }
    private void addRoundKey(byte[][] state, byte[][] roundKey) {
        for (int col = 0; col < Nb; col++) {
            int[] columnState = getColumn(state, col);
            int[] columnRoundKey = getColumn(roundKey, col);
            int[] result = new int[4];

            for (int i = 0; i < 4; i++) {
                result[i] = columnState[i] ^ columnRoundKey[i];
            }

            for (int i = 0; i < 4; i++) {
                state[i][col] = (byte) result[i];
            }
        }
    }
    private int[] getColumn(byte[][] matrix, int col) {
        int[] column = new int[4];
        for (int i = 0; i < 4; i++) {
            column[i] = matrix[i][col] & 0xFF;
        }
        return column;
    }
    private byte[] getColumnByte(byte[][] matrix, int col) {
        byte[] column = new byte[4];
        for (int i = 0; i < 4; i++) {
            column[i] = matrix[i][col];
        }
        return column;
    }

    private byte[][] getRoundKey(byte[][] expandedKey, int round) {
        byte[][] roundKey = new byte[4][Nb];
        int start = round * Nb;

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                roundKey[i][j] = expandedKey[i][(start + j)];
            }
        }

        return roundKey;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getKey() {
        return key;
    }

    public byte[] getEncrypt() {
        return encrypt;
    }

    public byte[] getDecript() {
        return decript;
    }
}
