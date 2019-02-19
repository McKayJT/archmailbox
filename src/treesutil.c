#include <ctype.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum COMMAND {
    NONE = 0,
    CREATE,
    CHANGEPW,
    ED25519
};

enum COMMAND mode = NONE;
bool VERBOSE = false;

struct user {
    unsigned char pubkey [crypto_box_PUBLICKEYBYTES];
    char pubkeystr [crypto_box_PUBLICKEYBYTES * 2 + 1];

    unsigned char privkey [crypto_box_SECRETKEYBYTES];

    unsigned char secretkey [crypto_secretbox_KEYBYTES];

    unsigned char salt [crypto_pwhash_SALTBYTES];
    char saltstr [crypto_pwhash_SALTBYTES * 2 + 1];

    unsigned char nonce [crypto_box_NONCEBYTES];
    char noncestr [crypto_box_NONCEBYTES * 2 + 1];

    unsigned char locked [crypto_box_SECRETKEYBYTES + crypto_secretbox_MACBYTES];
    char lockedstr [(crypto_box_SECRETKEYBYTES + crypto_secretbox_MACBYTES) * 2 + 1];
};
typedef struct user user_t;

static void
print_debug_hex(unsigned char *s, size_t len)
{
    int i;
    for(i=0; i < len; i++)
        fprintf(stderr, "%02x", s[i]);
    fprintf(stderr, "\n");
}

static void
usage(FILE* s)
{
    fputs("treesutil [-cpsvh]\n"
          " -h print this message\n"
          " -c create user\n"
          " -p change password\n"
          " -s create ed25519 keypair\n"
          " -v print debug output (insecure)\n"
          "man treeutil for details", s);
}

static void
die(bool showusage, char *m, ...)
{
    va_list ap;
    if(m != NULL) {
        va_start(ap, m);
        vfprintf(stderr, m, ap);
        va_end(ap);
    }
    if(showusage)
        usage(stderr);
    exit(EXIT_FAILURE);
}

/**
 * get count NULL-deliminated inputs from stdin
 *
 * exits program with failure if too few items found
 *
 * returned array and every item are allocated using malloc()
 */
static char**
getinputs(int count)
{
    char **out = NULL;
    char *line;
    int i;
    size_t n;
    ssize_t ret;

    out = malloc(sizeof(char *) * count);
    if(out == NULL) {
        perror("malloc");
        abort();
    }

    for(i = 0; i<count; i++) {
        line = NULL;
        n = 0;
        if(getdelim(&line, &n, '\0', stdin) == -1) {
            die(false, "not enough inputs; expected %d\n", count);
        }
        out[i] = line;
    }
    return out;
}

/**
 * output user structure
 *
 * prints null delim strings to stdout
 */
static void
printuser(user_t *user)
{
    printf("%s", user->pubkeystr);
    putc('\0', stdout);
    printf("%s", user->saltstr);
    putc('\0', stdout);
    printf("%s", user->noncestr);
    putc('\0', stdout);
    printf("%s", user->lockedstr);
    putc('\0', stdout);
}

/**
 * generate hex strings for user data
 */
static void
hexuser(user_t *user)
{
    sodium_bin2hex(user->saltstr, sizeof user->saltstr,
                   user->salt, sizeof user->salt);
    sodium_bin2hex(user->noncestr, sizeof user->noncestr,
                   user->nonce, sizeof user->nonce);
    sodium_bin2hex(user->pubkeystr, sizeof user->pubkeystr,
                   user->pubkey, sizeof user->pubkey);
    sodium_bin2hex(user->lockedstr, sizeof user->lockedstr,
                   user->locked, sizeof user->locked);

    if(VERBOSE) {
        fputs("generating user hex\n", stderr);
        fprintf(stderr, "public: %s\nsalt: %s\nnonce: %s\nlocked: %s\n",
                user->pubkeystr, user->saltstr, user->noncestr, user->lockedstr);
    }
}

/**
 * generate user data from hex strings
 */
static void
unhexuser(user_t *user)
{
    if(sodium_hex2bin(user->pubkey, sizeof user->pubkey,
                      user->pubkeystr, strlen(user->pubkeystr), NULL, NULL, NULL) != 0)
        die(false, "invalid publickey hex");
    if(sodium_hex2bin(user->salt, sizeof user->salt,
                      user->saltstr, strlen(user->saltstr), NULL, NULL, NULL) != 0)
        die(false, "invalid salt hex");
    if(sodium_hex2bin(user->nonce, sizeof user->nonce,
                      user->noncestr, strlen(user->noncestr), NULL, NULL, NULL) != 0)
        die(false, "invalid nonce hex");
    if(sodium_hex2bin(user->locked, sizeof user->locked,
                      user->lockedstr, strlen(user->lockedstr), NULL, NULL, NULL) != 0)
        die(false, "invalid locked box hex");

    if(VERBOSE) {
        fputs("making user from hex\n", stderr);
        fprintf(stderr, "public: ");
        print_debug_hex(user->pubkey, sizeof user->pubkey);
        fprintf(stderr, "salt: ");
        print_debug_hex(user->salt, sizeof user->salt);
        fprintf(stderr, "nonce: ");
        print_debug_hex(user->nonce, sizeof user->nonce);
        fprintf(stderr, "locked: ");
        print_debug_hex(user->locked, sizeof user->locked);
    }
}

/**
 * creates nonce, salt, and then uses password to create
 * secret key and encrypt privatekey
 */
static void
gensecrets(user_t *user, char *password)
{
    randombytes_buf(user->nonce, sizeof user->nonce);
    randombytes_buf(user->salt, sizeof user->salt);

    if(crypto_pwhash(user->secretkey, sizeof user->secretkey,
                     password, strlen(password), user->salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE,
                     crypto_pwhash_MEMLIMIT_INTERACTIVE,
                     crypto_pwhash_ALG_ARGON2ID13) != 0) {
        die(false, "key derivation fails for password");
    }

    if(VERBOSE) {
        fprintf(stderr, "Secret key: ");
        print_debug_hex(user->secretkey, sizeof user->secretkey);
    }

    crypto_secretbox_easy(user->locked, user->privkey, sizeof user->privkey,
                          user->nonce, user->secretkey);
}

/**
 * new user key creation
 *
 * takes 'password' in stdin
 * outputs pubkey, salt, nonce, lockedstr in hex format
 * delimited by nul
 */
static void
createuser()
{
    char **inputs;
    user_t user;

    inputs = getinputs(1);

    crypto_box_keypair(user.pubkey, user.privkey);
    gensecrets(&user, inputs[0]);
    hexuser(&user);
    printuser(&user);

    exit(EXIT_SUCCESS);
}

/**
 * Change user password
 *
 * input pubkey, salt, nonce, lockedstr in hex format
 * oldpassword, newpassword
 * inputs nul delimited
 * output pubkey, salt, nonce, lockedstr in hex format
 */
static void
changepw()
{
    char** inputs;
    user_t user;
    char* pubkeystr, *saltstr, *noncestr, *lockedstr, *oldpass, *newpass;
    unsigned char testpk[crypto_box_PUBLICKEYBYTES];

    inputs = getinputs(6);

    pubkeystr = inputs[0];
    saltstr = inputs[1];
    noncestr = inputs[2];
    lockedstr = inputs[3];
    oldpass = inputs[4];
    newpass = inputs[5];

    if(strlen(pubkeystr) != sizeof user.pubkeystr -1)
        die(false, "wrong pubkey length");
    if(strlen(saltstr) != sizeof user.saltstr - 1)
        die(false, "wrong salt length");
    if(strlen(noncestr) != sizeof user.noncestr - 1)
        die(false, "wrong nonce length");
    if(strlen(lockedstr) != sizeof user.lockedstr -1)
        die(false, "wrong locked box length");
    memcpy(user.pubkeystr, pubkeystr, sizeof user.pubkeystr);
    memcpy(user.saltstr, saltstr, sizeof user.saltstr);
    memcpy(user.noncestr, noncestr, sizeof user.noncestr);
    memcpy(user.lockedstr, lockedstr, sizeof user.lockedstr);

    unhexuser(&user);

    /* derive secretbox key from password and decrypt box */
    if(crypto_pwhash(user.secretkey, sizeof user.secretkey,
                     oldpass, strlen(oldpass), user.salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE,
                     crypto_pwhash_MEMLIMIT_INTERACTIVE,
                     crypto_pwhash_ALG_ARGON2ID13) != 0) {
        die(false, "key derivation fails for old password");
    }
    if(VERBOSE) {
        fprintf(stderr, "Secret key (old password): ");
        print_debug_hex(user.secretkey, sizeof user.secretkey);
    }
    if(crypto_secretbox_open_easy(user.privkey, user.locked, sizeof user.locked,
                                  user.nonce, user.secretkey) != 0)
        die(false, "invalid old password");

    crypto_scalarmult_base(testpk, user.privkey);
    if(sodium_memcmp(user.pubkey, testpk, sizeof testpk) != 0)
        die(false, "private key from box does not match public key provided");

    gensecrets(&user, newpass);
    hexuser(&user);
    printuser(&user);

    exit(EXIT_SUCCESS);
}

/**
 * generate ed25519 keypair
 * inputs: none
 * output: secret key, public key
 * delim ' '
 */
static void
gened25519()
{
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char seed[crypto_sign_SEEDBYTES];
    char seedb64[sodium_base64_ENCODED_LEN(crypto_sign_SEEDBYTES,
                                           sodium_base64_VARIANT_ORIGINAL)];
    char pkb64[sodium_base64_ENCODED_LEN(crypto_sign_PUBLICKEYBYTES,
                                         sodium_base64_VARIANT_ORIGINAL)];

    crypto_sign_keypair(pk, sk);
    crypto_sign_ed25519_sk_to_seed(seed, sk);
    sodium_bin2base64(seedb64, sizeof seedb64, seed, sizeof seed,
                      sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(pkb64, sizeof pkb64, pk, sizeof pk,
                      sodium_base64_VARIANT_ORIGINAL);

    printf("%s %s\n", seedb64, pkb64);
    exit(EXIT_SUCCESS);
}

static void
setcommand(enum COMMAND m)
{
    if(mode != NONE)
        die(true, "Only operation at a time is supported");
    mode = m;
}

int
main(int argc, char** argv)
{
    int f;

    if(sodium_init() == -1) {
        abort();
    }

    while((f = getopt(argc, argv, "cpshv")) != -1) {
        switch(f) {
        case 'c':
            setcommand(CREATE);
            break;
        case 'p':
            setcommand(CHANGEPW);
            break;
        case 's':
            setcommand(ED25519);
            break;
        case 'h':
            usage(stdout);
            exit(EXIT_SUCCESS);
            break;
        case 'v':
            VERBOSE = true;
            break;
        case '?':
            if (isprint (optopt))
                die(true, "Unknown option '-%c'\n", optopt);
            else
                die(true, "Unknown option character '\\x%x'\n", optopt);
            break;
        default:
            abort();
        }
    }

    if(mode == NONE)
        die(true, "Must specify an option");

    switch(mode) {
    case CREATE:
        createuser();
        break;
    case CHANGEPW:
        changepw();
        break;
    case ED25519:
        gened25519();
        break;
    default:
        abort();
    }

    exit(EXIT_SUCCESS);
}
