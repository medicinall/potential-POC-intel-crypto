# Schéma de preuve de concept pour tester une backdoor potentielle dans AES-GCM sur CPU Intel

## Vue d'ensemble

Ce document présente un schéma de preuve de concept en C pour tester et potentiellement démontrer l'existence d'une backdoor dans l'implémentation matérielle d'AES-GCM sur les processeurs Intel. Le code s'appuiera sur les points de vulnérabilité identifiés dans l'analyse documentaire et explorera les comportements suspects des instructions matérielles AES-NI et PCLMULQDQ.

## Structure du code

Le code sera organisé en plusieurs modules :

1. **Module de test principal** - Coordonne les différents tests et affiche les résultats
2. **Module d'implémentation de référence** - Implémentation logicielle pure d'AES-GCM
3. **Module d'implémentation matérielle** - Utilisation directe des instructions AES-NI et PCLMULQDQ
4. **Module de comparaison** - Analyse des différences entre les implémentations
5. **Module d'exploitation** - Tentatives d'exploitation des vulnérabilités identifiées

## Points clés à tester

1. **Génération de la clé de hachage H**
   - Comparaison entre H = AES_K(0^128) calculé en logiciel pur et via AES-NI
   - Test de valeurs spécifiques de clés pouvant déclencher un comportement anormal

2. **Opérations dans GF(2^128)**
   - Comparaison des multiplications dans GF(2^128) en logiciel et via PCLMULQDQ
   - Test de motifs spécifiques pouvant révéler des biais statistiques

3. **Manipulation du compteur J0**
   - Test de valeurs d'IV spécifiques pouvant déclencher un comportement anormal
   - Analyse des différences dans la dérivation de J0 entre logiciel et matériel

4. **Calcul et vérification du tag d'authentification**
   - Comparaison des tags générés par les deux implémentations
   - Test de conditions limites et de cas spéciaux

## Approche méthodologique

1. **Tests de comparaison directe**
   - Exécution des deux implémentations sur les mêmes entrées
   - Analyse des différences dans les sorties

2. **Tests statistiques**
   - Génération de grands ensembles de données chiffrées et de tags
   - Analyse statistique pour détecter des biais ou des motifs

3. **Tests de déclenchement**
   - Recherche de combinaisons spécifiques de clés, IV et données pouvant activer un comportement anormal
   - Test de séquences d'instructions particulières

4. **Tests de timing**
   - Mesure précise des temps d'exécution pour différentes entrées
   - Recherche d'anomalies de performance pouvant indiquer un traitement spécial

## Implémentation détaillée

### 1. Fonctions principales

```c
// Structure pour les contextes AES-GCM
typedef struct {
    // Contexte pour l'implémentation de référence
    void* ref_ctx;
    // Contexte pour l'implémentation matérielle
    void* hw_ctx;
    // Paramètres de configuration
    int key_len;
    int iv_len;
    int tag_len;
} aes_gcm_test_ctx_t;

// Initialisation des contextes de test
int init_test_contexts(aes_gcm_test_ctx_t* ctx, const uint8_t* key, int key_len);

// Exécution d'un test de comparaison
int run_comparison_test(aes_gcm_test_ctx_t* ctx, 
                       const uint8_t* iv, int iv_len,
                       const uint8_t* aad, int aad_len,
                       const uint8_t* plaintext, int pt_len,
                       uint8_t* ref_ciphertext, uint8_t* hw_ciphertext,
                       uint8_t* ref_tag, uint8_t* hw_tag);

// Analyse des différences
int analyze_differences(const uint8_t* ref_data, const uint8_t* hw_data, 
                       int data_len, const char* data_type);

// Test statistique sur un grand nombre d'échantillons
int run_statistical_test(aes_gcm_test_ctx_t* ctx, int num_samples);

// Test de déclenchement avec des valeurs spécifiques
int run_trigger_test(aes_gcm_test_ctx_t* ctx, const uint8_t* trigger_pattern);
```

### 2. Implémentation de référence (logicielle pure)

```c
// Implémentation de référence d'AES-GCM sans utilisation d'instructions matérielles
// Cette implémentation servira de base de comparaison

// Initialisation du contexte de référence
int ref_aes_gcm_init(void** ctx, const uint8_t* key, int key_len);

// Chiffrement AES-GCM de référence
int ref_aes_gcm_encrypt(void* ctx, 
                       const uint8_t* iv, int iv_len,
                       const uint8_t* aad, int aad_len,
                       const uint8_t* plaintext, int pt_len,
                       uint8_t* ciphertext,
                       uint8_t* tag, int tag_len);

// Déchiffrement AES-GCM de référence
int ref_aes_gcm_decrypt(void* ctx, 
                       const uint8_t* iv, int iv_len,
                       const uint8_t* aad, int aad_len,
                       const uint8_t* ciphertext, int ct_len,
                       uint8_t* plaintext,
                       const uint8_t* tag, int tag_len);

// Libération des ressources
void ref_aes_gcm_free(void* ctx);
```

### 3. Implémentation matérielle (utilisant AES-NI et PCLMULQDQ)

```c
// Implémentation d'AES-GCM utilisant directement les instructions matérielles
// Cette implémentation sera testée pour détecter des comportements anormaux

// Vérification de la disponibilité des instructions matérielles
int check_hw_support();

// Initialisation du contexte matériel
int hw_aes_gcm_init(void** ctx, const uint8_t* key, int key_len);

// Chiffrement AES-GCM matériel
int hw_aes_gcm_encrypt(void* ctx, 
                      const uint8_t* iv, int iv_len,
                      const uint8_t* aad, int aad_len,
                      const uint8_t* plaintext, int pt_len,
                      uint8_t* ciphertext,
                      uint8_t* tag, int tag_len);

// Déchiffrement AES-GCM matériel
int hw_aes_gcm_decrypt(void* ctx, 
                      const uint8_t* iv, int iv_len,
                      const uint8_t* aad, int aad_len,
                      const uint8_t* ciphertext, int ct_len,
                      uint8_t* plaintext,
                      const uint8_t* tag, int tag_len);

// Libération des ressources
void hw_aes_gcm_free(void* ctx);
```

### 4. Fonctions d'accès direct aux instructions matérielles

```c
// Fonctions d'accès direct aux instructions AES-NI

// Chiffrement AES d'un bloc avec AES-NI
void aesni_encrypt(const uint8_t* in, uint8_t* out, const void* key_schedule);

// Génération de la clé de hachage H
void aesni_generate_hash_key(const void* key_schedule, uint8_t* hash_key);

// Multiplication dans GF(2^128) avec PCLMULQDQ
void gf_multiply(const uint8_t* a, const uint8_t* b, uint8_t* res);

// Fonction GHASH utilisant PCLMULQDQ
void ghash_compute(const uint8_t* hash_key, 
                  const uint8_t* aad, int aad_len,
                  const uint8_t* ciphertext, int ct_len,
                  uint8_t* ghash_result);
```

### 5. Tests spécifiques pour détecter des backdoors

```c
// Test de clés faibles potentielles
int test_weak_keys(aes_gcm_test_ctx_t* ctx);

// Test de valeurs d'IV spécifiques
int test_special_ivs(aes_gcm_test_ctx_t* ctx);

// Test de collisions dans GHASH
int test_ghash_collisions(aes_gcm_test_ctx_t* ctx);

// Test de timing pour détecter des comportements anormaux
int test_timing_variations(aes_gcm_test_ctx_t* ctx);

// Test de séquences d'instructions spécifiques
int test_instruction_sequences(aes_gcm_test_ctx_t* ctx);
```

### 6. Fonction principale

```c
int main(int argc, char** argv) {
    // Vérification du support matériel
    if (!check_hw_support()) {
        printf("Les instructions AES-NI et/ou PCLMULQDQ ne sont pas disponibles sur ce processeur.\n");
        return -1;
    }
    
    // Initialisation des contextes de test
    aes_gcm_test_ctx_t ctx;
    uint8_t key[32]; // Clé de test
    
    // Génération d'une clé de test
    generate_random_data(key, sizeof(key));
    
    // Initialisation des contextes
    if (init_test_contexts(&ctx, key, sizeof(key)) != 0) {
        printf("Erreur lors de l'initialisation des contextes de test.\n");
        return -1;
    }
    
    // Exécution des tests de comparaison
    printf("Exécution des tests de comparaison...\n");
    run_basic_comparison_tests(&ctx);
    
    // Exécution des tests statistiques
    printf("Exécution des tests statistiques...\n");
    run_statistical_test(&ctx, 10000);
    
    // Exécution des tests de déclenchement
    printf("Recherche de motifs de déclenchement...\n");
    run_trigger_tests(&ctx);
    
    // Tests spécifiques pour détecter des backdoors
    printf("Exécution des tests de détection de backdoor...\n");
    test_weak_keys(&ctx);
    test_special_ivs(&ctx);
    test_ghash_collisions(&ctx);
    test_timing_variations(&ctx);
    test_instruction_sequences(&ctx);
    
    // Libération des ressources
    cleanup_test_contexts(&ctx);
    
    return 0;
}
```

## Compilation et exécution

```bash
# Compilation avec support pour les instructions AES-NI et PCLMULQDQ
gcc -maes -mpclmul -O2 -o aes_gcm_backdoor_test aes_gcm_backdoor_test.c -lcrypto

# Exécution
./aes_gcm_backdoor_test
```

## Résultats attendus

Le programme générera des rapports détaillés sur :

1. Les différences détectées entre les implémentations logicielles et matérielles
2. Les anomalies statistiques dans les sorties
3. Les combinaisons d'entrées déclenchant des comportements anormaux
4. Les variations de timing suspectes
5. Les potentielles faiblesses ou backdoors identifiées

Ces résultats permettront d'évaluer la présence potentielle d'une backdoor dans l'implémentation matérielle d'AES-GCM sur les processeurs Intel.
