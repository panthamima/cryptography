#ifndef H_RIJNDAEL
#define H_RIJNDAEL

int  rijndael_setup_encrypt(unsigned long *round_key, const unsigned char *key, int keybits);
int  rijndael_setup_decrypt(unsigned long *round_key, const unsigned char *key, int keybits);

void rijndael_encrypt(const unsigned long *round_key, int number_round, const unsigned char plaintext[16], unsigned char ciphertext[16]);
void rijndael_decrypt(const unsigned long *round_key, int number_round, const unsigned char plaintext[16], unsigned char ciphertext[16]);

#define KEYLENGTH(keybits)       ((keybits)/8)
#define ROUND_KEY_LEGTH(keybits) ((keybits)/8)
#define NUMBER_ROUNDS(keybits)   ((keybits)/8)

#endif