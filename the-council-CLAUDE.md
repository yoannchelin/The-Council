# CLAUDE.md — The Council

> Briefing pour reprendre ce projet dans une nouvelle session Claude ou Claude Code.
> Lis ce fichier **en entier** avant d'écrire la moindre ligne.

---

## 1. Le projet en une phrase

**The Council** est le **méta-agent coordinateur** de l'écosystème. Il lit les tables de tous les autres agents, corrèle leurs signaux, et produit un **plan d'amélioration priorisé** : *"voici les 10 zones à traiter en premier, classées par impact potentiel, avec la justification multi-signaux"*. Un seul outil MCP — `assess_repo` — retourne une vue complète de la santé du repo.

The Council **ne génère pas de code**, **n'analyse pas le code directement**, et **n'a besoin d'aucun LLM au cœur**. Il agrège des scores existants. Le LLM côté client (Claude Desktop) présente et explique.

---

## 2. Dépendances — ce que The Council lit

The Council est le seul agent qui lit **toutes** les tables. Il ne peut fonctionner utilement qu'une fois les autres agents déployés.

| Agent | Tables lues | Signal apporté |
|---|---|---|
| **Git Archaeologist** | `symbols`, `files`, `edges`, `commits`, `file_commits`, `meta` | Call graph, churn brut, architecture |
| **Blast Radius** | `blast_metrics` | Risk score, fan-in, transitive_in |
| **Test Sentinel** | `sentinel_coverage`, `sentinel_findings` | Coverage qualitative, trous de tests |
| **Bug Hunter** | `hunter_file_stats`, `hunter_findings` | Historique de bugs, patterns d'erreurs |
| **Dep Sentinel** | `dep_vulnerabilities`, `dep_modules` | CVEs, licences, modules abandonnés |

**Dégradation gracieuse** : si un agent n'a pas tourné (ses tables sont vides), The Council ignore ce signal et le mentionne dans le rapport. Il ne crashe pas.

Tables écrites par The Council : `council_assessments`, `council_action_items`. Préfixe `council_*`.

---

## 3. Le modèle de corrélation — comment les signaux se combinent

The Council attribue un **score de priorité composite** à chaque zone (fichier ou symbole). Ce score combine les signaux disponibles :

```
priority = (
    blast_risk_score   * 0.30   +  -- impact si ça casse
    sentinel_gap       * 0.25   +  -- pas de tests sur une zone critique
    hunter_fix_ratio   * 0.25   +  -- historique de bugs dans cette zone
    dep_vuln_score     * 0.20      -- CVE dans une dépendance utilisée ici
) * presence_bonus
```

`presence_bonus` : multiplicateur si 3+ signaux convergent sur la même zone (ex: blast_risk élevé + pas de tests + historique de bugs = ×1.5).

Les zones sans aucun signal d'alerte ne sont pas listées — The Council ne rapporte que ce qui mérite attention.

---

## 4. Schema SQLite (`council_*`)

```sql
-- Un assessment = une analyse complète du repo à un instant T
CREATE TABLE council_assessments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      INTEGER NOT NULL,  -- unix seconds
    repo_path       TEXT NOT NULL,
    agents_present  TEXT NOT NULL,  -- JSON array : ["archaeo","blast","sentinel","hunter","dep"]
    summary         TEXT NOT NULL,  -- JSON : stats globales
    health_score    REAL NOT NULL   -- 0..100, score global de santé
);

-- Les action items : ce que le dev devrait faire en priorité
CREATE TABLE council_action_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id   INTEGER NOT NULL REFERENCES council_assessments(id),
    rank            INTEGER NOT NULL,    -- 1 = plus urgent
    kind            TEXT NOT NULL,
    -- 'fix_untested_critical' : fonction critique sans tests
    -- 'fix_buggy_zone'        : zone avec historique de bugs + blast élevé
    -- 'patch_vulnerability'   : CVE avec fix disponible
    -- 'investigate_coupling'  : couplage implicite dangereux
    -- 'add_coverage'          : coverage manquante sur zone à risque
    -- 'review_license'        : licence incompatible
    -- 'replace_abandoned'     : module abandonné avec CVE
    priority_score  REAL NOT NULL,
    signals         TEXT NOT NULL,  -- JSON : quels agents ont contribué
    qualified       TEXT,           -- symbole ou fichier concerné
    path            TEXT,
    headline        TEXT NOT NULL,  -- phrase humaine, ex: "ChargeCustomer a blast radius 40 et 0 tests"
    action          TEXT NOT NULL   -- ce qu'il faut faire concrètement
);
CREATE INDEX idx_council_items_rank ON council_action_items(assessment_id, rank);

CREATE TABLE council_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

---

## 5. Les outils MCP

The Council expose **2 outils** — c'est volontairement minimal.

### `assess_repo`
Lance une analyse complète et retourne :
- `health_score` : 0–100, score global
- `agents_present` : quels agents ont contribué
- `top_action_items` : les 10 premières actions, classées par priorité
- `signal_summary` : combien de findings par agent
- `convergence_zones` : zones où 3+ signaux convergent (les plus dangereuses)

Input : rien (prend le repo configuré au démarrage du serveur).
Option : `top_n` (défaut 10), `min_priority` (filtre par score).

### `explain_zone`
Pour un fichier ou symbole donné, explique pourquoi il est flagué : quels signaux convergent, quelles actions sont recommandées.

Input : `path` ou `qualified` (nom qualifié du symbole).

---

## 6. Layout du projet

```
cmd/
  council/         CLI : `council assess | top | explain`
  council-mcp/     Binaire MCP stdio
internal/
  store/           Ouvre DB archaeo, lit toutes les tables _*, écrit council_*
  signals/         Collecte et normalise les signaux de chaque agent
  correlate/       Algorithme de corrélation + scoring composite
  report/          Génère les action items + health score
  mcpserver/       Les 2 outils MCP
```

---

## 7. Décisions architecturales

| Décision | Raison |
|---|---|
| **Score composite pondéré, pas ML** | Simple, auditable, tunable. Les poids sont dans `correlate/weights.go` et configurables sans recompile. Pas de modèle à entraîner. |
| **Dégradation gracieuse** | The Council doit être utile même si seulement 2 agents ont tourné. Il mentionne les agents absents dans le rapport mais ne bloque pas. |
| **`convergence_zones` comme concept central** | Une zone flagée par 3 agents est exponentiellement plus risquée qu'une zone flagée par 1. C'est l'insight que les agents individuels ne peuvent pas donner. |
| **2 outils MCP seulement** | The Council est un agrégateur, pas un outil d'exploration. `assess_repo` = vue globale, `explain_zone` = drill-down. Pas besoin de plus. |
| **Pas de LLM dans The Council** | Le LLM côté client (Claude) fait la synthèse narrative. The Council fournit des données structurées propres. Mettre un LLM dans The Council ajouterait un coût et du non-déterminisme sans valeur. |
| **Sauvegarde des assessments** | Chaque `council assess` est sauvegardé avec timestamp. Permet de comparer la santé du repo dans le temps. |

---

## 8. Ce que The Council ne fait pas

- Il ne relit pas le code source
- Il ne génère pas de code ou de tests
- Il ne modifie aucune table des autres agents
- Il ne contacte aucun service externe
- Il ne remplace pas les agents individuels — il les complète

---

## 9. Exemple de rapport (texte brut)

```
Council Assessment — 2026-05-21
Health score: 42/100
Agents present: archaeo ✓, blast ✓, sentinel ✓, hunter ✓, dep ✗

TOP 10 ACTION ITEMS

1. [score 94] FIX UNTESTED CRITICAL
   internal/payment/charge.go — ChargeCustomer
   → blast radius 47, 0 tests directs, 2 bugs fixes dans 3 mois
   Action: Écrire des tests pour les cas d'erreur (montant négatif, provider nil)

2. [score 87] PATCH VULNERABILITY
   golang.org/x/crypto@v0.0.1 — GO-2024-2387 (CRITICAL, CVSS 9.1)
   → utilisé dans internal/auth/ qui a blast radius 89
   Action: Mettre à jour vers v0.31.0

3. [score 76] INVESTIGATE COUPLING
   internal/db/query.go ↔ internal/cache/redis.go
   → modifiés ensemble dans 8 commits de fix, aucun edge dans le call graph
   Action: Documenter ou formaliser cette dépendance implicite

...

CONVERGENCE ZONES (3+ signaux)
  internal/payment/ : blast élevé + pas de tests + historique de bugs
  internal/auth/    : blast élevé + CVE dans dépendance
```

---

## 10. Pièges à anticiper

- **Les tables peuvent être partiellement peuplées** — `blast_metrics` peut avoir des rows mais pas pour tous les symboles. Toujours `LEFT JOIN` et traiter les NULL comme "signal absent".
- **Les assessments s'accumulent** — prévoir une commande `council purge --older-than 30d` pour éviter la croissance infinie de la DB.
- **Le health score est subjectif** — les pondérations dans `correlate/weights.go` sont des heuristiques. Documenter clairement leur signification pour que l'utilisateur puisse les ajuster.
- **Les paths relatifs vs absolus** — chaque agent peut stocker les chemins différemment. Normaliser vers des chemins relatifs à `repoRoot` dans `store/store.go`.
- **Logs sur stderr uniquement** dans `council-mcp`.

---

## 11. Ordre de construction

The Council est le dernier agent à construire. Prérequis : au moins Archaeologist + Blast + 1 autre agent doivent avoir tourné.

1. `internal/store` — lecteur multi-tables + tables council_*
2. `internal/signals` — collecte et normalisation (1 struct par agent)
3. `internal/correlate` — scoring composite + convergence zones
4. `internal/report` — action items + health score
5. CLI `council assess`
6. `internal/mcpserver` — 2 outils MCP

---

## 12. Commandes utiles

```bash
# Lancer après que tous les agents ont tourné
council assess --repo /path/to/repo
council top --repo /path/to/repo --n 5
council explain --repo /path/to/repo --path internal/payment/charge.go

council-mcp --repo /path/to/repo
```

Claude Desktop config :
```json
{
  "mcpServers": {
    "council": {
      "command": "/abs/path/bin/council-mcp",
      "args": ["--repo", "/abs/path/to/repo"]
    }
  }
}
```

---

## 13. Comment reprendre

1. Lis ce fichier en entier.
2. Vérifie que tous les agents ont tourné sur le repo cible (au minimum archaeo + blast).
3. Commence par `internal/store` — le lecteur multi-tables est la base de tout.
4. Implémente `internal/signals` agent par agent — chaque agent est une struct indépendante.
5. Mets à jour ce fichier si tu prends une décision archi ou découvres un piège.

---

## 14. Vision finale de l'écosystème

```
Question posée à Claude Desktop :
"Qu'est-ce que je devrais améliorer en priorité dans ce repo ?"

→ Claude appelle council-mcp → assess_repo
→ The Council lit toutes les tables blast_* sentinel_* hunter_* dep_*
→ Corrèle les signaux, calcule les priorités
→ Retourne un plan structuré
→ Claude présente : "Voici les 3 zones critiques et pourquoi..."

Total : ~2s, 0 appel réseau, 0 token LLM côté serveur.
```
