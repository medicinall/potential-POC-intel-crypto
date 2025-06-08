#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <time.h>

// Pour l'accès potentiel aux intrinsics (si disponibles et configurés)
#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h> // Pour AES-NI et PCLMULQDQ
#include <cpuid.h>     // Pour __get_cpuid
#endif

// Définitions et structures
#define AES_BLOCK_SIZE 16
#define GCM_TAG_MAX_SIZE 16

// Structure pour les contextes AES-GCM
typedef struct {
    EVP_CIPHER_CTX* ref_ctx_encrypt;
    EVP_CIPHER_CTX* ref_ctx_decrypt;
    // Pour une implémentation matérielle simulée ou réelle
    uint8_t hw_key[32]; 
    int hw_key_len;
    const EVP_CIPHER* cipher_type;
    int key_len_bits;
} aes_gcm_test_ctx_t;

// Prototypes des fonctions
int check_hw_support();
void generate_random_data(uint8_t* data, size_t len);
void print_hex(const char* label, const uint8_t* data, size_t len);
long long current_timestamp_ns();

int init_test_contexts(aes_gcm_test_ctx_t* ctx, const uint8_t* key, int key_len_bytes);
void cleanup_test_contexts(aes_gcm_test_ctx_t* ctx);

// Fonctions de chiffrement/déchiffrement de référence (OpenSSL)
int ref_aes_gcm_encrypt(aes_gcm_test_ctx_t* ctx, const uint8_t* iv, int iv_len,
                        const uint8_t* aad, int aad_len, const uint8_t* plaintext, int pt_len,
                        uint8_t* ciphertext, int* ct_len, uint8_t* tag, int tag_len);
int ref_aes_gcm_decrypt(aes_gcm_test_ctx_t* ctx, const uint8_t* iv, int iv_len,
                        const uint8_t* aad, int aad_len, const uint8_t* ciphertext, int ct_len,
                        uint8_t* plaintext, int* pt_len, const uint8_t* tag, int tag_len);

// Fonctions de chiffrement/déchiffrement "matérielles" (simulées pour l'exemple)
// Dans un cas réel, celles-ci utiliseraient directement les instructions AES-NI/PCLMULQDQ
int hw_aes_gcm_encrypt_simulated(aes_gcm_test_ctx_t* ctx, const uint8_t* iv, int iv_len,
                                 const uint8_t* aad, int aad_len, const uint8_t* plaintext, int pt_len,
                                 uint8_t* ciphertext, int* ct_len, uint8_t* tag, int tag_len);
int hw_aes_gcm_decrypt_simulated(aes_gcm_test_ctx_t* ctx, const uint8_t* iv, int iv_len,
                                 const uint8_t* aad, int aad_len, const uint8_t* ciphertext, int ct_len,
                                 uint8_t* plaintext, int* pt_len, const uint8_t* tag, int tag_len);

// Fonctions de test
int run_basic_comparison_tests(aes_gcm_test_ctx_t* ctx);
int run_statistical_test(aes_gcm_test_ctx_t* ctx, int num_samples);
int run_trigger_tests(aes_gcm_test_ctx_t* ctx);
int test_weak_keys_simulation(aes_gcm_test_ctx_t* ctx);
int test_special_ivs_simulation(aes_gcm_test_ctx_t* ctx);
int test_ghash_collisions_simulation(aes_gcm_test_ctx_t* ctx);
int test_timing_variations(aes_gcm_test_ctx_t* ctx);
int test_instruction_sequences_simulation(aes_gcm_test_ctx_t* ctx);

// Implémentation de la vérification du support matériel
int check_hw_support() {
    printf("Vérification du support matériel (AES-NI, PCLMULQDQ) :\n");
#if defined(__x86_64__) || defined(_M_X64)
    unsigned int eax, ebx, ecx, edx;
    // Vérifier AES-NI (ECX bit 25 après CPUID EAX=1)
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if (!(ecx & (1 << 25))) {
            printf("  AES-NI n'est pas supporté.\n");
            return 0;
        } else {
            printf("  AES-NI est supporté.\n");
        }
        // Vérifier PCLMULQDQ (ECX bit 1 après CPUID EAX=1)
        if (!(ecx & (1 << 1))) {
            printf("  PCLMULQDQ n'est pas supporté.\n");
            return 0;
        } else {
            printf("  PCLMULQDQ est supporté.\n");
        }
    } else {
        printf("  Impossible d'exécuter CPUID.\n");
        return 0; // Impossible de vérifier
    }
    return 1; 
#else
    printf("  Non applicable pour cette architecture (pas x86-64).\n");
    return 0; // Non supporté sur les architectures non-x86 pour cet exemple
#endif
}

void generate_random_data(uint8_t* data, size_t len) {
    if (RAND_bytes(data, len) != 1) {
        fprintf(stderr, "Erreur lors de la génération de données aléatoires : %s\n", ERR_error_string(ERR_get_error(), NULL));
        // Gérer l'erreur
    }
}

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s (%zu octets): ", label, len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

long long current_timestamp_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000L + ts.tv_nsec;
}

int init_test_contexts(aes_gcm_test_ctx_t* ctx, const uint8_t* key, int key_len_bytes) {
    ctx->ref_ctx_encrypt = EVP_CIPHER_CTX_new();
    ctx->ref_ctx_decrypt = EVP_CIPHER_CTX_new();
    ctx->key_len_bits = key_len_bytes * 8;
    memcpy(ctx->hw_key, key, key_len_bytes);
    ctx->hw_key_len = key_len_bytes;

    if (!ctx->ref_ctx_encrypt || !ctx->ref_ctx_decrypt) {
        fprintf(stderr, "Erreur d'allocation pour EVP_CIPHER_CTX.\n");
        return -1;
    }

    switch (ctx->key_len_bits) {
        case 128: ctx->cipher_type = EVP_aes_128_gcm(); break;
        case 192: ctx->cipher_type = EVP_aes_192_gcm(); break;
        case 256: ctx->cipher_type = EVP_aes_256_gcm(); break;
        default:
            fprintf(stderr, "Longueur de clé non supportée : %d bits\n", ctx->key_len_bits);
            EVP_CIPHER_CTX_free(ctx->ref_ctx_encrypt);
            EVP_CIPHER_CTX_free(ctx->ref_ctx_decrypt);
            return -1;
    }
    printf("Contextes de test initialisés (Référence OpenSSL et préparation pour HW simulé).\n");
    return 0;
}

void cleanup_test_contexts(aes_gcm_test_ctx_t* ctx) {
    if (ctx->ref_ctx_encrypt) EVP_CIPHER_CTX_free(ctx->ref_ctx_encrypt);
    if (ctx->ref_ctx_decrypt) EVP_CIPHER_CTX_free(ctx->ref_ctx_decrypt);
    printf("Contextes de test nettoyés.\n");
}

int ref_aes_gcm_encrypt(aes_gcm_test_ctx_t* ctx, const uint8_t* iv, int iv_len,
                        const uint8_t* aad, int aad_len, const uint8_t* plaintext, int pt_len,
                        uint8_t* ciphertext, int* ct_len, uint8_t* tag, int tag_len) {
    int len;
    *ct_len = 0;

    if (1 != EVP_EncryptInit_ex(ctx->ref_ctx_encrypt, ctx->cipher_type, NULL, NULL, NULL)) return -1;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx->ref_ctx_encrypt, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) return -1;
    if (1 != EVP_EncryptInit_ex(ctx->ref_ctx_encrypt, NULL, NULL, ctx->hw_key, iv)) return -1;
    if (aad && aad_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx->ref_ctx_encrypt, NULL, &len, aad, aad_len)) return -1;
    }
    if (plaintext && pt_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx->ref_ctx_encrypt, ciphertext, &len, plaintext, pt_len)) return -1;
        *ct_len = len;
    }
    if (1 != EVP_EncryptFinal_ex(ctx->ref_ctx_encrypt, ciphertext + *ct_len, &len)) return -1;
    *ct_len += len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx->ref_ctx_encrypt, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) return -1;
    return 0;
}

int ref_aes_gcm_decrypt(aes_gcm_test_ctx_t* ctx, const uint8_t* iv, int iv_len,
                        const uint8_t* aad, int aad_len, const uint8_t* ciphertext, int ct_len,
                        uint8_t* plaintext, int* pt_len, const uint8_t* tag, int tag_len) {
    int len;
    *pt_len = 0;

    if (1 != EVP_DecryptInit_ex(ctx->ref_ctx_decrypt, ctx->cipher_type, NULL, NULL, NULL)) return -1;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx->ref_ctx_decrypt, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) return -1;
    if (1 != EVP_DecryptInit_ex(ctx->ref_ctx_decrypt, NULL, NULL, ctx->hw_key, iv)) return -1;
    if (aad && aad_len > 0) {
        if (1 != EVP_DecryptUpdate(ctx->ref_ctx_decrypt, NULL, &len, aad, aad_len)) return -1;
    }
    if (ciphertext && ct_len > 0) {
        if (1 != EVP_DecryptUpdate(ctx->ref_ctx_decrypt, plaintext, &len, ciphertext, ct_len)) return -1;
        *pt_len = len;
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx->ref_ctx_decrypt, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag)) return -1;
    if (1 != EVP_DecryptFinal_ex(ctx->ref_ctx_decrypt, plaintext + *pt_len, &len)) return -1; // Vérification du tag
    *pt_len += len;
    return 0;
}

// Simulation d'une implémentation matérielle (utilise OpenSSL pour la démo)
// Dans un cas réel, il faudrait ici appeler les intrinsics AES-NI/PCLMULQDQ
int hw_aes_gcm_encrypt_simulated(aes_gcm_test_ctx_t* ctx, const uint8_t* iv, int iv_len,
                                 const uint8_t* aad, int aad_len, const uint8_t* plaintext, int pt_len,
                                 uint8_t* ciphertext, int* ct_len, uint8_t* tag, int tag_len) {
    // Pour la simulation, on réutilise l'implémentation de référence.
    // Une backdoor pourrait être simulée ici en modifiant subtilement les données ou le tag
    // sous certaines conditions (par ex. une valeur d'IV spécifique).
    return ref_aes_gcm_encrypt(ctx, iv, iv_len, aad, aad_len, plaintext, pt_len, ciphertext, ct_len, tag, tag_len);
}

int hw_aes_gcm_decrypt_simulated(aes_gcm_test_ctx_t* ctx, const uint8_t* iv, int iv_len,
                                 const uint8_t* aad, int aad_len, const uint8_t* ciphertext, int ct_len,
                                 uint8_t* plaintext, int* pt_len, const uint8_t* tag, int tag_len) {
    return ref_aes_gcm_decrypt(ctx, iv, iv_len, aad, aad_len, ciphertext, ct_len, plaintext, pt_len, tag, tag_len);
}


int run_basic_comparison_tests(aes_gcm_test_ctx_t* ctx) {
    printf("\n--- Test de Comparaison de Base ---\n");
    uint8_t iv[12];
    uint8_t aad[16];
    uint8_t plaintext[64];
    uint8_t ref_ciphertext[128], hw_ciphertext[128];
    uint8_t ref_tag[GCM_TAG_MAX_SIZE], hw_tag[GCM_TAG_MAX_SIZE];
    int ref_ct_len, hw_ct_len;
    int ref_pt_len, hw_pt_len;
    uint8_t decrypted_ref[128], decrypted_hw[128];

    generate_random_data(iv, sizeof(iv));
    generate_random_data(aad, sizeof(aad));
    generate_random_data(plaintext, sizeof(plaintext));

    print_hex("IV        ", iv, sizeof(iv));
    print_hex("AAD       ", aad, sizeof(aad));
    print_hex("Plaintext ", plaintext, sizeof(plaintext));

    // Chiffrement de référence
    if (ref_aes_gcm_encrypt(ctx, iv, sizeof(iv), aad, sizeof(aad), plaintext, sizeof(plaintext), ref_ciphertext, &ref_ct_len, ref_tag, GCM_TAG_MAX_SIZE) != 0) {
        fprintf(stderr, "Erreur de chiffrement de référence.\n"); return -1;
    }
    print_hex("Ref CT    ", ref_ciphertext, ref_ct_len);
    print_hex("Ref Tag   ", ref_tag, GCM_TAG_MAX_SIZE);

    // Chiffrement "matériel" (simulé)
    if (hw_aes_gcm_encrypt_simulated(ctx, iv, sizeof(iv), aad, sizeof(aad), plaintext, sizeof(plaintext), hw_ciphertext, &hw_ct_len, hw_tag, GCM_TAG_MAX_SIZE) != 0) {
        fprintf(stderr, "Erreur de chiffrement matériel simulé.\n"); return -1;
    }
    print_hex("HW CT     ", hw_ciphertext, hw_ct_len);
    print_hex("HW Tag    ", hw_tag, GCM_TAG_MAX_SIZE);

    if (ref_ct_len != hw_ct_len || memcmp(ref_ciphertext, hw_ciphertext, ref_ct_len) != 0) {
        printf("ERREUR : Les textes chiffrés diffèrent ! Possible indication de backdoor/anomalie.\n");
    } else {
        printf("OK : Les textes chiffrés correspondent.\n");
    }
    if (memcmp(ref_tag, hw_tag, GCM_TAG_MAX_SIZE) != 0) {
        printf("ERREUR : Les tags diffèrent ! Possible indication de backdoor/anomalie.\n");
    } else {
        printf("OK : Les tags correspondent.\n");
    }

    // Déchiffrement
    if (ref_aes_gcm_decrypt(ctx, iv, sizeof(iv), aad, sizeof(aad), ref_ciphertext, ref_ct_len, decrypted_ref, &ref_pt_len, ref_tag, GCM_TAG_MAX_SIZE) != 0) {
        fprintf(stderr, "Erreur de déchiffrement de référence.\n"); return -1;
    }
    if (hw_aes_gcm_decrypt_simulated(ctx, iv, sizeof(iv), aad, sizeof(aad), hw_ciphertext, hw_ct_len, decrypted_hw, &hw_pt_len, hw_tag, GCM_TAG_MAX_SIZE) != 0) {
        fprintf(stderr, "Erreur de déchiffrement matériel simulé.\n"); return -1;
    }

    if (ref_pt_len != sizeof(plaintext) || memcmp(plaintext, decrypted_ref, sizeof(plaintext)) != 0) {
         printf("ERREUR : Le déchiffrement de référence a échoué.\n");
    } else {
        printf("OK : Le déchiffrement de référence a réussi.\n");
    }
     if (hw_pt_len != sizeof(plaintext) || memcmp(plaintext, decrypted_hw, sizeof(plaintext)) != 0) {
         printf("ERREUR : Le déchiffrement matériel simulé a échoué. Possible indication de backdoor/anomalie si le tag était correct.\n");
    } else {
        printf("OK : Le déchiffrement matériel simulé a réussi.\n");
    }
    return 0;
}

int run_statistical_test(aes_gcm_test_ctx_t* ctx, int num_samples) {
    printf("\n--- Test Statistique (Simulation) ---\n");
    printf("NOTE : Ce test est une simulation. Une analyse statistique réelle nécessiterait des outils plus avancés \n");
    printf("       et une implémentation matérielle réelle pour comparer les distributions des sorties (tags, CT) \n");
    printf("       afin de détecter des biais subtils qui pourraient indiquer une backdoor.\n");
    // Exemple : compter les bits à 1 dans les tags sur de nombreux échantillons
    // et comparer la distribution entre ref et hw.
    // Pour l'instant, on exécute juste quelques chiffrements.
    for (int i = 0; i < 3; ++i) { // Petit nombre pour la démo
        uint8_t iv[12], aad[16], plaintext[32];
        uint8_t ref_ct[64], hw_ct[64];
        uint8_t ref_tag[GCM_TAG_MAX_SIZE], hw_tag[GCM_TAG_MAX_SIZE];
        int ref_ct_len, hw_ct_len;
        generate_random_data(iv, sizeof(iv));
        generate_random_data(aad, sizeof(aad));
        generate_random_data(plaintext, sizeof(plaintext));
        ref_aes_gcm_encrypt(ctx, iv, sizeof(iv), aad, sizeof(aad), plaintext, sizeof(plaintext), ref_ct, &ref_ct_len, ref_tag, GCM_TAG_MAX_SIZE);
        hw_aes_gcm_encrypt_simulated(ctx, iv, sizeof(iv), aad, sizeof(aad), plaintext, sizeof(plaintext), hw_ct, &hw_ct_len, hw_tag, GCM_TAG_MAX_SIZE);
        if (memcmp(ref_tag, hw_tag, GCM_TAG_MAX_SIZE) != 0) {
             printf("  Différence de tag détectée dans le test statistique (échantillon %d) !\n", i);
        }
    }
    printf("Test statistique simulé terminé. Vérifiez les différences de tags ci-dessus.\n");
    return 0;
}

int run_trigger_tests(aes_gcm_test_ctx_t* ctx) {
    printf("\n--- Test de Déclencheurs (Simulation) ---\n");
    printf("NOTE : Ce test simule la recherche de déclencheurs (valeurs d'IV ou AAD spécifiques) \n");
    printf("       qui pourraient activer une backdoor. Une backdoor pourrait, par exemple, \n");
    printf("       produire un tag prédictible ou divulguer la clé pour un IV donné.\n");
    uint8_t specific_iv[12] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}; // Exemple d'IV "magique"
    uint8_t aad[16], plaintext[32];
    uint8_t ref_ct[64], hw_ct[64];
    uint8_t ref_tag[GCM_TAG_MAX_SIZE], hw_tag[GCM_TAG_MAX_SIZE];
    int ref_ct_len, hw_ct_len;

    generate_random_data(aad, sizeof(aad));
    generate_random_data(plaintext, sizeof(plaintext));

    printf("Test avec IV spécifique :\n");
    print_hex("IV Spéc.  ", specific_iv, sizeof(specific_iv));
    ref_aes_gcm_encrypt(ctx, specific_iv, sizeof(specific_iv), aad, sizeof(aad), plaintext, sizeof(plaintext), ref_ct, &ref_ct_len, ref_tag, GCM_TAG_MAX_SIZE);
    hw_aes_gcm_encrypt_simulated(ctx, specific_iv, sizeof(specific_iv), aad, sizeof(aad), plaintext, sizeof(plaintext), hw_ct, &hw_ct_len, hw_tag, GCM_TAG_MAX_SIZE);
    
    print_hex("Ref Tag   ", ref_tag, GCM_TAG_MAX_SIZE);
    print_hex("HW Tag    ", hw_tag, GCM_TAG_MAX_SIZE);
    if (memcmp(ref_tag, hw_tag, GCM_TAG_MAX_SIZE) != 0) {
        printf("  DIFFÉRENCE DE TAG pour IV spécifique ! Potentiel déclencheur de backdoor.\n");
    } else {
        printf("  Tags identiques pour IV spécifique.\n");
    }
    // Ici, on pourrait aussi vérifier si hw_tag est une valeur connue/faible.
    printf("Test de déclencheurs simulé terminé.\n");
    return 0;
}

int test_timing_variations(aes_gcm_test_ctx_t* ctx) {
    printf("\n--- Test de Variations de Timing (Concept) ---\n");
    printf("NOTE : Ce test mesurerait le temps d'exécution des opérations de chiffrement/déchiffrement \n");
    printf("       matérielles pour différentes entrées. Des variations de temps inattendues \n");
    printf("       (par ex., beaucoup plus long pour certaines clés/IV) pourraient indiquer \n");
    printf("       un traitement spécial par une backdoor (ex: exfiltration de clé).\n");
    
    long long start_time, end_time, ref_duration, hw_duration;
    uint8_t iv[12], aad[16], plaintext[1024]; // Plus grand pour mieux voir les variations
    uint8_t ref_ct[1050], hw_ct[1050];
    uint8_t ref_tag[GCM_TAG_MAX_SIZE], hw_tag[GCM_TAG_MAX_SIZE];
    int ref_ct_len, hw_ct_len;

    generate_random_data(iv, sizeof(iv));
    generate_random_data(aad, sizeof(aad));
    generate_random_data(plaintext, sizeof(plaintext));

    start_time = current_timestamp_ns();
    ref_aes_gcm_encrypt(ctx, iv, sizeof(iv), aad, sizeof(aad), plaintext, sizeof(plaintext), ref_ct, &ref_ct_len, ref_tag, GCM_TAG_MAX_SIZE);
    end_time = current_timestamp_ns();
    ref_duration = end_time - start_time;

    start_time = current_timestamp_ns();
    hw_aes_gcm_encrypt_simulated(ctx, iv, sizeof(iv), aad, sizeof(aad), plaintext, sizeof(plaintext), hw_ct, &hw_ct_len, hw_tag, GCM_TAG_MAX_SIZE);
    end_time = current_timestamp_ns();
    hw_duration = end_time - start_time;

    printf("Durée chiffrement référence : %lld ns\n", ref_duration);
    printf("Durée chiffrement HW (sim)  : %lld ns\n", hw_duration);
    printf("Une différence significative et consistante pour certaines entrées pourrait être suspecte.\n");
    return 0;
}

// Les fonctions suivantes sont des coquilles pour montrer où les tests plus avancés iraient.
int test_weak_keys_simulation(aes_gcm_test_ctx_t* ctx) {
    printf("\n--- Test de Clés Faibles (Concept) ---\n");
    printf("Concept : Testerait si certaines clés produisent des keystreams faibles ou des tags prédictibles \n");
    printf("          dans l'implémentation matérielle.\n");
    return 0;
}
int test_special_ivs_simulation(aes_gcm_test_ctx_t* ctx) {
    printf("\n--- Test d'IV Spéciaux (Concept Avancé) ---\n");
    printf("Concept : Approfondir le test de déclencheurs avec une gamme plus large d'IV suspects.\n");
    return 0;
}
int test_ghash_collisions_simulation(aes_gcm_test_ctx_t* ctx) {
    printf("\n--- Test de Collisions GHASH (Concept) ---\n");
    printf("Concept : Tenter de trouver des collisions dans la fonction GHASH matérielle, \n");
    printf("          ce qui pourrait permettre des forgeries de tag si H est manipulé.\n");
    return 0;
}
int test_instruction_sequences_simulation(aes_gcm_test_ctx_t* ctx) {
    printf("\n--- Test de Séquences d'Instructions (Concept) ---\n");
    printf("Concept : Tester si des séquences spécifiques d'appels aux fonctions cryptographiques \n");
    printf("          matérielles activent un comportement de backdoor.\n");
    return 0;
}


int main(int argc, char** argv) {
    if (!check_hw_support()) {
        printf("Tests de backdoor matérielle impossibles sans support AES-NI/PCLMULQDQ.\n");
        // On pourrait continuer avec des tests purement logiciels si pertinent
    }

    aes_gcm_test_ctx_t ctx_s;
    uint8_t key[32]; // AES-256
    generate_random_data(key, sizeof(key));
    print_hex("Clé de test", key, sizeof(key));

    if (init_test_contexts(&ctx_s, key, sizeof(key)) != 0) {
        return -1;
    }

    printf("\n========== DÉBUT DES TESTS DE DÉTECTION DE BACKDOOR POTENTIELLE ==========\n");

    run_basic_comparison_tests(&ctx_s);
    run_statistical_test(&ctx_s, 100); // Petit nombre pour la démo
    run_trigger_tests(&ctx_s);
    test_timing_variations(&ctx_s);
    
    // Tests conceptuels plus avancés (actuellement des coquilles)
    test_weak_keys_simulation(&ctx_s);
    test_special_ivs_simulation(&ctx_s);
    test_ghash_collisions_simulation(&ctx_s);
    test_instruction_sequences_simulation(&ctx_s);

    printf("\n========== FIN DES TESTS DE DÉTECTION DE BACKDOOR POTENTIELLE ==========\n");

    cleanup_test_contexts(&ctx_s);

    printf("\nLe programme de test de backdoor AES-GCM s'est terminé.\n");
    printf("IMPORTANT : Ce code fournit un CADRE et des SIMULATIONS pour les tests de backdoor.\n");
    printf("           Une analyse réelle nécessite une implémentation MATÉRIELLE DIRECTE (pas simulée) \n");
    printf("           des fonctions hw_aes_gcm_encrypt/decrypt utilisant les intrinsics AES-NI/PCLMULQDQ, \n");
    printf("           ainsi que des analyses statistiques et cryptographiques beaucoup plus poussées.\n");
    printf("           Les 'détections' actuelles sont basées sur la comparaison avec une simulation qui, \n");
    printf("           par défaut, se comporte comme la référence. Pour détecter une vraie backdoor, \n");
    printf("           il faudrait que l'implémentation matérielle réelle dévie de la référence.\n");

    return 0;
}
