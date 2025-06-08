# Points techniques relatifs aux potentielles backdoors dans AES-GCM sur CPU Intel

## 1. Points critiques dans l'implémentation matérielle

### 1.1 Instructions AES-NI et PCLMULQDQ
- Les instructions AES-NI (Advanced Encryption Standard New Instructions) sont des extensions du jeu d'instructions x86 spécifiques à Intel
- L'instruction PCLMULQDQ (Carry-Less Multiplication Quadword) est utilisée pour les multiplications dans GF(2^128)
- Ces instructions sont opaques et leur implémentation matérielle n'est pas entièrement documentée
- Le contrôle de ces instructions est entièrement délégué au hardware, sans possibilité de vérification par le logiciel

### 1.2 Génération de la clé de hachage H
- La clé de hachage H est dérivée directement de la clé AES par H = AES_K(0^128)
- Cette opération est critique et souvent implémentée via AES-NI
- Une modification subtile de cette dérivation pourrait affaiblir l'ensemble du système sans être détectable

### 1.3 Opérations dans le champ de Galois GF(2^128)
- Les multiplications dans GF(2^128) sont effectuées via l'instruction PCLMULQDQ
- Le polynôme irréductible utilisé est x^128+x^7+x^2+x+1
- Une implémentation modifiée pourrait introduire des biais statistiques ou des faiblesses mathématiques

## 2. Vecteurs d'attaque potentiels

### 2.1 Manipulation du compteur J0
- Le compteur initial J0 est dérivé de l'IV et est crucial pour la sécurité
- Une implémentation matérielle pourrait introduire des biais dans cette dérivation
- Des valeurs spécifiques d'IV pourraient déclencher un comportement anormal non documenté

### 2.2 Affaiblissement de la fonction GHASH
- GHASH est une fonction linéaire par rapport aux données d'entrée pour un H donné
- Une implémentation matérielle pourrait introduire des collisions ou des faiblesses pour certaines valeurs de H
- La linéarité de GHASH pourrait être exploitée si l'implémentation matérielle présente des biais

### 2.3 Fuites d'information via canaux auxiliaires
- Les implémentations matérielles peuvent présenter des fuites via timing, consommation électrique ou EMI
- Les instructions AES-NI sont supposées résistantes aux attaques par canal auxiliaire, mais cette résistance dépend de l'implémentation matérielle
- Des comportements spécifiques pourraient être déclenchés par des séquences d'instructions particulières

## 3. Mécanismes potentiels de backdoor

### 3.1 Affaiblissement cryptographique ciblé
- Génération de clés H faibles pour certaines clés AES spécifiques
- Introduction de biais statistiques dans les opérations de multiplication GF(2^128)
- Réduction de l'entropie effective pour certaines combinaisons de clés et d'IV

### 3.2 Déclencheurs cachés
- Séquences spécifiques d'opérations pouvant activer un mode de fonctionnement alternatif
- Valeurs particulières d'IV ou de compteurs pouvant déclencher un comportement non standard
- Combinaisons de données et d'opérations pouvant révéler des informations sur la clé

### 3.3 Manipulation du tag d'authentification
- Affaiblissement du calcul du tag pour certaines configurations
- Introduction de collisions prévisibles dans le calcul de GHASH
- Manipulation du processus de vérification pour permettre des forgeries dans des cas spécifiques

## 4. Points d'investigation pour la preuve de concept

### 4.1 Analyse des implémentations de référence Intel
- Comparaison entre implémentations logicielles et matérielles
- Recherche de divergences subtiles dans les résultats pour certaines entrées
- Analyse des performances et comportements pour des cas limites

### 4.2 Tests de détection de biais
- Génération et analyse statistique de grands ensembles de tags d'authentification
- Recherche de motifs ou biais dans les sorties pour des entrées spécifiques
- Tests de collision pour identifier des faiblesses potentielles

### 4.3 Exploitation des caractéristiques matérielles
- Utilisation directe des instructions AES-NI et PCLMULQDQ
- Manipulation des registres et états internes du processeur
- Exploration des comportements non documentés ou ambigus
