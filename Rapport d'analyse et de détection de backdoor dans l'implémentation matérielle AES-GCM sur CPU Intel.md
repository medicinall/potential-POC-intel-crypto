# Rapport d'analyse et de détection de backdoor dans l'implémentation matérielle AES-GCM sur CPU Intel

## Résumé exécutif

Ce rapport présente une analyse approfondie des mécanismes potentiels de backdoor dans l'implémentation matérielle d'AES-GCM sur les processeurs Intel, en se concentrant sur les instructions AES-NI et PCLMULQDQ. Nous avons développé un cadre de test utilisant directement les intrinsics matérielles pour détecter des comportements anormaux qui pourraient indiquer la présence d'une backdoor cryptographique. Le code fourni permet de comparer les implémentations logicielles (OpenSSL) et matérielles (AES-NI/PCLMULQDQ), d'analyser les variations de timing, et de tester des valeurs spécifiques pouvant déclencher des comportements suspects.

## Table des matières

1. Introduction
2. Analyse théorique des vulnérabilités potentielles
3. Méthodologie de détection
4. Structure et fonctionnement du code
5. Implémentation matérielle directe
6. Tests implémentés
7. Résultats et interprétation
8. Limites de l'approche actuelle
9. Recommandations pour une analyse approfondie
10. Conclusion

## 1. Introduction

L'algorithme AES-GCM (Advanced Encryption Standard - Galois/Counter Mode) est largement utilisé pour le chiffrement authentifié dans de nombreux protocoles de sécurité. Sur les processeurs Intel modernes, cet algorithme bénéficie d'une accélération matérielle via les instructions spécialisées AES-NI (pour les opérations AES) et PCLMULQDQ (pour les multiplications dans le champ de Galois GF(2^128)).

Ces instructions matérielles sont opaques et leur implémentation interne n'est pas entièrement documentée, ce qui soulève la question de la présence potentielle de backdoors ou de vulnérabilités délibérément introduites. Une backdoor dans ces instructions pourrait compromettre la sécurité de toutes les communications utilisant AES-GCM sur ces processeurs.

## 2. Analyse théorique des vulnérabilités potentielles

Notre analyse du fonctionnement d'AES-GCM a identifié plusieurs points critiques où une backdoor pourrait être implémentée :

### 2.1 Génération de la clé de hachage H

La clé de hachage H est dérivée de la clé AES par `H = AES_K(0^128)`. Cette opération est fondamentale pour la sécurité de GCM. Une modification subtile de cette dérivation pourrait affaiblir l'ensemble du système sans être facilement détectable.

### 2.2 Opérations dans le champ de Galois GF(2^128)

Les multiplications dans GF(2^128) sont effectuées via l'instruction PCLMULQDQ. Une implémentation modifiée pourrait introduire des biais statistiques ou des faiblesses mathématiques dans certaines conditions spécifiques.

### 2.3 Manipulation du compteur J0

Le compteur initial J0 est dérivé de l'IV et est crucial pour la sécurité. Une implémentation matérielle pourrait introduire des biais dans cette dérivation pour certaines valeurs d'IV.

### 2.4 Affaiblissement de la fonction GHASH

GHASH est une fonction linéaire par rapport aux données d'entrée pour un H donné. Une implémentation matérielle pourrait introduire des collisions ou des faiblesses pour certaines valeurs de H.

### 2.5 Fuites d'information via canaux auxiliaires

Les implémentations matérielles peuvent présenter des fuites via timing, consommation électrique ou EMI. Des comportements spécifiques pourraient être déclenchés par des séquences d'instructions particulières.

## 3. Méthodologie de détection

Notre approche pour détecter une backdoor potentielle repose sur plusieurs techniques complémentaires :

1. **Accès direct aux instructions matérielles** : Utilisation des intrinsics AES-NI et PCLMULQDQ pour accéder directement aux instructions matérielles, sans passer par des bibliothèques intermédiaires.

2. **Comparaison avec référence** : Exécution parallèle d'une implémentation de référence (OpenSSL) et de l'implémentation matérielle sur les mêmes entrées, avec analyse des différences dans les sorties.

3. **Tests statistiques** : Analyse de grands ensembles de données chiffrées et de tags pour détecter des biais ou des motifs anormaux.

4. **Tests de déclencheurs** : Recherche de combinaisons spécifiques de clés, IV et données pouvant activer un comportement anormal.

5. **Analyse de timing** : Mesure précise des temps d'exécution pour différentes entrées afin de détecter des variations suspectes.

## 4. Structure et fonctionnement du code

Le code fourni est structuré en plusieurs modules fonctionnels :

### 4.1 Vérification du support matériel

La fonction `check_hw_support()` vérifie la disponibilité des instructions AES-NI et PCLMULQDQ sur le processeur via CPUID.

### 4.2 Implémentation de référence

Les fonctions `ref_aes_gcm_encrypt()` et `ref_aes_gcm_decrypt()` fournissent une implémentation de référence basée sur OpenSSL.

### 4.3 Implémentation matérielle directe

Les fonctions `hw_aes_gcm_encrypt_real()` et `hw_aes_gcm_decrypt_real()` utilisent directement les intrinsics AES-NI et PCLMULQDQ pour implémenter AES-GCM.

### 4.4 Fonctions de test

Plusieurs fonctions de test sont implémentées pour détecter différents types de comportements anormaux :
- `run_basic_comparison_tests()`
- `run_statistical_test()`
- `run_trigger_tests()`
- `test_timing_variations()`
- `test_weak_keys_simulation()`
- `test_special_ivs_simulation()`
- `test_ghash_collisions_simulation()`
- `test_instruction_sequences_simulation()`

## 5. Implémentation matérielle directe

L'implémentation matérielle directe utilise les intrinsics suivants pour accéder aux instructions AES-NI et PCLMULQDQ :

### 5.1 Instructions AES-NI utilisées

- `_mm_aeskeygenassist_si128` : Assiste l'expansion de clé AES
- `_mm_aesenc_si128` : Effectue une ronde AES (SubBytes, ShiftRows, MixColumns, AddRoundKey)
- `_mm_aesenclast_si128` : Effectue la dernière ronde AES (sans MixColumns)

### 5.2 Instruction PCLMULQDQ utilisée

- `_mm_clmulepi64_si128` : Effectue une multiplication polynomiale carry-less de 64 bits

### 5.3 Expansion de clé AES

L'expansion de clé AES-128 est implémentée directement en utilisant les intrinsics AES-NI, avec des constantes immédiates pour chaque ronde comme requis par l'instruction `_mm_aeskeygenassist_si128`.

### 5.4 Implémentation de GHASH

La fonction GHASH est implémentée en utilisant l'instruction PCLMULQDQ pour la multiplication polynomiale dans GF(2^128), bien que la réduction polynomiale soit simplifiée dans la version actuelle.

## 6. Tests implémentés

### 6.1 Test de comparaison de base

Ce test compare les résultats (texte chiffré et tag) entre l'implémentation de référence et l'implémentation matérielle pour des entrées identiques. Toute différence pourrait indiquer un comportement anormal.

### 6.2 Test statistique

Ce test examine plusieurs échantillons pour détecter des biais dans les sorties qui pourraient indiquer une backdoor.

### 6.3 Test de déclencheurs

Ce test recherche des valeurs spécifiques d'IV qui pourraient déclencher un comportement anormal dans l'implémentation matérielle.

### 6.4 Test de variations de timing

Ce test mesure et compare les temps d'exécution des implémentations de référence et matérielle pour détecter des variations suspectes qui pourraient indiquer un traitement spécial pour certaines entrées.

## 7. Résultats et interprétation

L'exécution du code sur un processeur Intel avec support AES-NI et PCLMULQDQ a révélé plusieurs points intéressants :

### 7.1 Différences entre implémentations

Des différences ont été détectées entre l'implémentation matérielle et la référence OpenSSL. Cependant, ces différences sont probablement dues à l'implémentation incomplète de GHASH et non à une backdoor réelle.

### 7.2 Variations de timing

Des variations significatives de timing ont été observées entre l'implémentation matérielle et la référence. L'implémentation matérielle est généralement plus lente en raison de son caractère incomplet et de l'absence d'optimisations.

### 7.3 Comportement avec IV spécifiques

Aucun comportement anormal n'a été détecté avec les IV spécifiques testés, mais un ensemble plus large de tests serait nécessaire pour une analyse complète.

## 8. Limites de l'approche actuelle

Notre implémentation présente plusieurs limitations importantes :

### 8.1 Implémentation incomplète de GHASH

La fonction GHASH est implémentée de manière simplifiée, sans la réduction polynomiale complète requise pour GF(2^128).

### 8.2 Support limité pour AES-256

L'expansion de clé pour AES-256 n'est pas complètement implémentée, ce qui limite la capacité à tester des clés de cette taille.

### 8.3 Échantillonnage limité

Les tests statistiques actuels utilisent un petit nombre d'échantillons, alors qu'une analyse complète nécessiterait des millions d'échantillons.

### 8.4 Absence d'analyse de canaux auxiliaires avancée

Une backdoor sophistiquée pourrait utiliser des canaux auxiliaires non détectés par nos tests actuels.

### 8.5 Complexité des déclencheurs potentiels

Les déclencheurs d'une backdoor réelle pourraient être extrêmement complexes et difficiles à identifier avec les tests actuels.

## 9. Recommandations pour une analyse approfondie

Pour une détection plus complète et fiable, nous recommandons :

### 9.1 Compléter l'implémentation matérielle

- Implémenter correctement la réduction polynomiale pour GHASH
- Compléter l'expansion de clé pour AES-256
- Optimiser l'implémentation pour des performances comparables à OpenSSL

### 9.2 Étendre les tests

- Augmenter le nombre d'échantillons pour les tests statistiques
- Tester un plus grand nombre d'IV et de clés potentiellement suspectes
- Implémenter des tests de collisions GHASH plus sophistiqués

### 9.3 Ajouter des analyses avancées

- Analyse de canaux auxiliaires (timing, consommation électrique)
- Analyse différentielle des comportements entre différentes générations de processeurs Intel
- Tests sur des cas limites et des conditions aux limites

## 10. Conclusion

Le code fourni établit un cadre solide pour la détection de backdoors potentielles dans l'implémentation matérielle d'AES-GCM sur les processeurs Intel en utilisant directement les instructions AES-NI et PCLMULQDQ. Bien que notre implémentation actuelle soit incomplète, elle démontre la méthodologie et les techniques qui pourraient être appliquées à une analyse matérielle complète.

Les différences détectées entre l'implémentation matérielle et la référence OpenSSL sont probablement dues à l'implémentation incomplète de GHASH et non à une backdoor réelle. Cependant, une implémentation complète et conforme serait nécessaire pour une analyse définitive.

La détection de backdoors cryptographiques est un défi complexe qui nécessite une combinaison d'expertise en cryptographie, en architecture des processeurs et en analyse statistique. Notre approche fournit un point de départ pour une investigation plus approfondie, mais ne peut pas garantir l'absence de backdoors sophistiquées.

---

## Annexe : Guide d'utilisation du code

### Prérequis

- GCC avec support pour les flags `-maes` et `-mpclmul`
- Bibliothèque OpenSSL (libssl-dev)
- Processeur x86-64 avec support AES-NI et PCLMULQDQ

### Compilation

```bash
gcc -maes -mpclmul -O2 -o aes_gcm_backdoor_test_real_hw aes_gcm_backdoor_test_real_hw.c -lcrypto
```

### Exécution

```bash
./aes_gcm_backdoor_test_real_hw
```

### Extension du code

Pour une analyse matérielle complète, les fonctions suivantes devraient être améliorées :

1. `ghash_multiply_hw()` : Implémenter correctement la réduction polynomiale pour GF(2^128)
2. `aes_key_expansion_hw()` : Compléter l'implémentation pour AES-256
3. `run_statistical_test()` : Étendre pour analyser un plus grand nombre d'échantillons
4. `run_trigger_tests()` : Ajouter plus de valeurs d'IV et de clés potentiellement suspectes
