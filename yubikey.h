#ifndef yubikey_h_
#define yubikey_h_

#define SESAME_CHALLENGE_SIZE 32
#define SESAME_RESPONSE_BUFFER_SIZE 64
#define SESAME_RESPONSE_SIZE 64
#define MAX_YUBIKEYS 1024

void sesame_yubikey_init();
int sesame_yubikey_challenge_response(unsigned int key_serial, int slot,
                                      const unsigned char* challenge,
                                      unsigned char* response,
                                      int* not_found,
                                      int* timed_out);

#endif /* yubikey_h_ */
