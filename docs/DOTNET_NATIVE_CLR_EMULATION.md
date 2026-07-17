# Émulation native des PE .NET/MSIL — Voie A (CLR réel)

Document de conception. Objectif : exécuter un exécutable managé (.NET Framework
ou .NET Core/5+) dans Brovan **sans ajouter de second moteur**, en chargeant le
**vrai CLR** (coreclr/clrjit, ou clr/clrjit/mscoree) comme n'importe quelle autre
DLL système et en laissant son JIT produire du x86-64 que le backend
Unicorn/KVM exécute — exactement comme un vrai process .NET sur Windows.

Ce document décrit **la Voie A uniquement**. La Voie B (interpréteur CIL dédié +
shims BCL, façon Avroke.Emulator) est mentionnée seulement comme repli au §13.

> **Statut : conception / non implémenté.** Aucune ligne de la Voie A n'existe
> aujourd'hui. Ce fichier fixe l'analyse, les points d'accroche réels et un plan
> par étapes mesurables pour que le travail soit repris sans re-dériver le
> contexte (même esprit que `docs/AL_KHASER_EMULATION.md`).

---

## 0. TL;DR

- **Faisable ?** Oui, et c'est la voie la plus cohérente avec l'ADN de Brovan
  (« on exécute le vrai binaire jusqu'à la frontière syscall »). Le CLR n'est
  architecturalement qu'une DLL native de plus, mappée par le loader ntdll du
  guest et exécutée par le backend.
- **Coût ?** Élevé. On fait transiter des millions d'instructions de CLR init +
  JIT + GC à travers l'émulateur, on dépend de l'exécution de **code produit à
  l'exécution** (JIT), et il faut embarquer le runtime + le framework managé.
  C'est un objectif long terme, pas un patch.
- **Ce qui joue en notre faveur :** (1) le versant **statique** .NET est déjà
  fait (détection COR20 + métadonnées + IL par méthode) ; (2) le modèle
  **real-DLL → syscall** est déjà en place avec **217 handlers `Nt*`**, un vrai
  loader ntdll, PEB/TEB/ApiSetMap, relocations et SEH ; (3) embarquer une vraie
  DLL supplémentaire dans `WindowsLibs` est un **pattern déjà établi** (le
  runtime VC++ et les tables NLS y sont déjà, cf. `AL_KHASER_EMULATION.md`) ;
  (4) le backend Unicorn/TCG gère nativement le **code auto-modifiant** (SMC),
  prérequis du JIT.
- **Le vrai pivot technique** n'est pas « comprendre le MSIL » (le CLR s'en
  charge) mais **survivre au bootstrap du CLR** : assez de syscalls `Nt*`, TLS,
  gestion des exceptions, et exécution fiable des pages JIT (RW→RX).

---

## 1. Rappel : le modèle d'exécution de Brovan

Brovan est un émulateur **CPU natif x86-64** (backends Unicorn et KVM,
`Core/Emulation/Backends/`). Son environnement Windows est **fidèle par
exécution du code réel**, pas par stubs synthétiques :

| Élément | Où | Ce qu'il fait |
|---|---|---|
| Chargement image principale | `Guests/WindowsGuest.cs::Initialize` (l.104) | mappe le PE par sections, applique les relocations, prépare PEB/TEB/ProcessParameters (`PrepareWinEnvironment`, l.1240) |
| Loader ntdll **réel** | `WindowsGuest.cs::LoadNtdll` (l.1558) | mappe la **vraie** `ntdll.dll` depuis `WindowsLibs`, puis résout `LdrInitializeThunk` / `RtlUserThreadStart` (l.870/881) |
| DLL dépendantes | pilotées par le loader **du guest** | seule ntdll est mappée au bootstrap ; kernel32/user32/… sont chargées par le **vrai `LdrInitializeThunk`** via `NtOpenFile`/`NtCreateSection`/`NtMapViewOfSection`, résolus depuis `WindowsLibs` |
| Mapping d'un module | `BinaryEmulator.WindowsBridge.cs::MapPeImageBySections` (l.1334) | mappe n'importe quel PE par sections + relocations (`ApplyPERelocations`) |
| Frontière d'interception | `BinaryEmulator.cs` hook `Syscall` (l.387) | le code natif réel des DLL s'exécute **jusqu'à l'instruction `syscall`**, servie par les 217 handlers `Nt*` |
| Surface syscall | `Core/Emulation/OS/Windows/**/Nt*.cs` | 217 handlers (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateSection`, `NtMapViewOfSection`, `NtCreateThreadEx`, `NtContinue`, …) |
| Provisioning DLL/données | `WindowsLibs/` (`GeneralHelper.cs:159`) + VFS `VirtualFS/` (`GeneralHelper.cs:922`) | vraies DLL système, `SysWOW64/`, `.nls`, runtime VC++, `apisetmap.bin` |

**Conséquence directe pour le .NET :** pour faire tourner du managé, on n'écrit
pas un CLR — on **fournit le vrai** et on laisse le loader du guest le charger,
puis on colmate ce que son bootstrap exerce. C'est la même mécanique qui a permis
à al-khaser d'atteindre ~24 M d'instructions.

---

## 2. Ce que Brovan sait déjà faire du .NET (statique)

À réutiliser, pas à refaire :

- Détection : `BinaryFile.cs:319/341` — `OptionalHeader.DataDirectory[14]`
  (COM descriptor) ⇒ `PE.DotNetStatus = DotNetStatus.DotNet`. Signature
  métadonnées `BSJB` absente ⇒ `ModifiedDotNet` (l.398).
- En-tête CLR : `IMAGE_COR20_HEADER` (`BinaryHelpers.cs:195`), lu en l.390.
- Métadonnées : `ParseDotNetFunctions()` (`BinaryFile.cs:1719`) via
  `System.Reflection.Metadata` — types, méthodes, champs, propriétés, **et le
  bytecode IL par méthode** (tiny/fat header, `CodeSize`, locals).
- UI : commande `bininfo dotnet` (`EmulationMenu.cs:1952`).

Ce que Brovan **ne** fait pas : exécuter. Aujourd'hui il n'existe **aucun**
garde-fou runtime sur `DotNetStatus` — un PE .NET est traité comme un PE natif et
l'exécution saute sur son `AddressOfEntryPoint`. `mscoree`/`clr`/`coreclr` ne
sont **ni fournis ni gérés** (aucune référence dans le code). Résultat concret :

- **.NET Framework x86 legacy** : l'entrypoint est le stub `jmp [__CorExeMain]`
  (IAT → `mscoree.dll!_CorExeMain`). `mscoree` étant absent de `WindowsLibs`, le
  bind d'import ou le premier `jmp` échoue → `[MISS]`/faute quasi immédiate.
- **.NET Core / AnyCPU** : l'assembly managé ne peut pas s'auto-démarrer
  nativement ; il n'y a pas de code natif utile à l'entrypoint.

Donc : **zéro exécution MSIL aujourd'hui**, seulement du parsing.

---

## 3. Ce qu'« exécuter du .NET nativement » implique réellement

Un PE managé ne contient pas de code natif « métier » : son corps est du
**CIL/MSIL**, compilé à la volée par le JIT du CLR. Le CLR est un gros composant
natif (init, chargeur d'assemblies, **JIT qui écrit du code exécutable en
mémoire**, GC avec son propre gestionnaire mémoire + write-barriers, TLS, EH
managé au-dessus du SEH natif, threading). Deux chaînes de bootstrap distinctes :

### 3.a .NET Framework (CLR « monolithique », v4.0.30319)

```
app.exe (managé)
  └─ entrypoint natif = jmp [mscoree!_CorExeMain]        (x86 ; x64 : shim COR)
       └─ mscoree.dll  (shim très fin)  → mscoreei.dll   → sélectionne la version
            └─ clr.dll  (le runtime)     charge mscorlib.dll (GAC), init GC/TLS
                 └─ clrjit.dll  JIT: CIL → x86-64 en mémoire RW→RX
                      └─ exécute Main() managé
```
Dépendances : `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `clrjit.dll`,
`mscorlib.dll` (+ le GAC / `C:\Windows\Microsoft.NET\Framework[64]\v4.0.30319\`).
Avantage : self-contained, chaîne courte, entrypoint classique.

### 3.b .NET Core / 5+ (host + coreclr)

```
app.exe (apphost natif — lanceur généré, pas managé)
  └─ hostfxr.dll   lit app.runtimeconfig.json, localise le framework
       └─ hostpolicy.dll  lit app.deps.json, construit la TPA list
            └─ coreclr.dll  init GC/TLS, charge System.Private.CoreLib.dll
                 └─ clrjit.dll  JIT: CIL → x86-64
                      └─ exécute Main() managé
```
Dépendances : `apphost`/`app.exe`, `hostfxr.dll`, `hostpolicy.dll`,
`coreclr.dll`, `clrjit.dll`, `System.Private.CoreLib.dll` + le dossier framework
`Microsoft.NETCore.App/<ver>/` **et** les fichiers `*.runtimeconfig.json` /
`*.deps.json` dans le VFS. Le host fait beaucoup de résolution
fichiers/JSON avant même que coreclr démarre.

> Pour une assembly managée « nue » (`app.dll`), le lanceur est `dotnet.exe`
> (lui-même un apphost). Le cas « single-file publish » ajoute une extraction de
> bundle — **hors périmètre du premier jalon**.

---

## 4. Pourquoi la Voie A colle à l'architecture

Le point décisif : **Brovan exécute le vrai `LdrInitializeThunk` de ntdll**. Le
chargement des DLL dépendantes n'est pas codé côté hôte — c'est le loader du
guest qui, à partir des imports, appelle les syscalls de mapping. Donc :

- mapper le CLR = **aucun code hôte spécifique** : on dépose les DLL du runtime
  dans `WindowsLibs`, le loader du guest les mappe via `NtCreateSection` +
  `NtMapViewOfSection` (`Files/NtCreateSection.cs`, `Files/NtMapViewOfSection.cs`)
  comme il mappe déjà kernel32 ;
- le CLR s'exécute comme du code natif normal, intercepté seulement aux
  `syscall` ;
- la **cohérence** (PEB/TEB, ApiSetMap, versions Windows, SEH, threads) est déjà
  celle d'un vrai process.

En une phrase : *du point de vue de Brovan, coreclr est « juste une DLL de plus »
et Main() managé est « juste du code JIT-é ».* Tout le travail est de rendre ce
chemin **survivable**.

---

## 5. Le pivot technique n°1 : exécuter le code produit par le JIT

C'est le risque central de la Voie A. Le JIT écrit des octets x86-64 dans une
page, puis les exécute. Trois sous-problèmes :

1. **Code auto-modifiant (SMC).** Après que le JIT a écrit du code, le backend
   doit ne pas exécuter une traduction périmée. **Mesuré au spike J0 (§5.d) :**
   Unicorn/TCG invalide correctement les translation blocks pour les écritures
   **pilotées par le guest** (le cas du JIT : le compilateur JIT s'exécute comme
   du code guest qui écrit dans le tas de code puis y saute) — validé par T2 +
   T3b. **Exception mesurée** : une écriture **côté hôte** (`uc_mem_write`, ex.
   un handler syscall ou le mapping d'image) sur une page **déjà exécutée/mise
   en cache** n'est **pas** auto-invalidée en 2.1.4 → octets périmés ré-exécutés
   (T3a). Mitigation **validée** : `uc_ctl_remove_cache(begin, end)` sur la plage
   écrite (T4). `UnicornBinding/Unicorn.cs` n'expose aujourd'hui que `FlushTlb`
   (`UC_CTL_TLB_FLUSH`, l.1278) et le buffer TCG (`UC_CTL_TCG_BUFFER_SIZE`,
   l.1307) — **il manque `remove_cache`** (voir le correctif requis en §5.d).
   Backend **KVM** : SMC natif (vrai matériel), pas de cache TCG.
2. **Transitions de protection RW→RX.** Le JIT alloue en `PAGE_READWRITE` (ou
   RWX), écrit, puis bascule en `PAGE_EXECUTE_READ` via
   `NtProtectVirtualMemory`. Handler déjà présent
   (`Process/NtProtectVirtualMemory.cs`) ; la table de protections
   `WinSyscallsHelper.cs:2427-2459` couvre déjà `PAGE_EXECUTE*`. **Mesuré (T1)** :
   le flip RW→RX exécute bien les octets fraîchement écrits, et exécuter la page
   **avant** le flip faute correctement (NX appliqué — W^X réel, pas RWX
   permanent). **Attention (mesuré)** : `uc_mem_protect` **ne flush pas** le
   cache TCG ; le flip fonctionne pour une émission neuve (page NX jamais mise en
   cache), mais une séquence RX→RW→(écriture hôte)→RX sur une page déjà exécutée
   exige un `remove_cache` explicite (idem point 1).
3. **Write-watch / barrières GC.** Le GC .NET utilise `MEM_WRITE_WATCH`
   (`NtAllocateVirtualMemory` + `NtGetWriteWatch`/`NtResetWriteWatch`) pour le
   card-marking de la génération éphémère. Brovan a déjà un `WriteWatchManager`
   (`BinaryEmulator.cs:363`). **À confirmer** : la précision par page attendue
   par le GC. (Hors périmètre du spike J0.)

> Note FAQ (`FAQ.md`) : sous Unicorn il faut **désactiver Control Flow Guard**
> pour l'hôte. C'est cohérent avec le fait que le JIT génère des cibles
> d'appel dynamiques ; à garder en tête pour le code JIT du guest.

### 5.d — Résultats mesurés du spike J0

Harnais : **`scripts/jit_spike_j0.py`** (reproductible : `python3
scripts/jit_spike_j0.py`). Il pilote **le moteur natif identique** à celui de
`UnicornBackend` (Unicorn **2.1.4**, mêmes primitives `uc_mem_map` /
`uc_mem_write` / `uc_mem_protect` / `uc_emu_start` — l'enum `MemoryProtection` de
Brovan **est** `UC_PROT_*`, passé tel quel). x86-64.

| Test | Ce qu'il prouve | Résultat |
|---|---|---|
| **T0** sanity RWX | encodages corrects ; code écrit à l'exécution s'exécute | **PASS** |
| **T1** RW→RX (W^X fidèle) | NX appliqué avant flip ; octets frais exécutés après flip = chemin `NtProtectVirtualMemory` | **PASS** |
| **T2** code émis par le guest | des instructions guest écrivent du code (`rep movsb`) puis `call` dedans | **PASS** |
| **T3b** SMC intra-run | le guest patche du code déjà exécuté puis le rappelle dans le même run | **PASS** |
| **T4** écriture hôte + `remove_cache` | mitigation de l'écriture hôte sur code caché | **PASS** |
| T3a écriture hôte brute | *caractérisation* : sans `remove_cache`, octets périmés ré-exécutés | STALE (attendu) |

**Verdict J0 (jambe Unicorn) : GO.** Les 5 tests JIT-critiques passent — la
capacité d'exécuter du code produit à l'exécution (émission, W^X RW→RX, codegen
guest + auto-modification) est validée sur le moteur exact de Brovan.

**Correctif requis dans Brovan (pré-requis avant J3+).** Ajouter au binding
Unicorn un `RemoveCache(begin, end)` et l'appeler sur **toute écriture hôte
(`WriteMemory`) qui touche une plage exécutable** (handlers syscall, application
de relocations, hooks). Modèle exact sur le `FlushTlb` existant
(`UnicornBinding/Unicorn.cs:1278`) mais avec `UC_CTL_TB_REMOVE_CACHE = 9`, sens
écriture, **2 arguments** `(begin, end)` :

```csharp
// control = UC_CTL_TB_REMOVE_CACHE(9) | (argc=2 << 26) | (UC_CTL_IO_WRITE(1) << 30)
public bool RemoveCache(ulong begin, ulong end) {
    const int UC_CTL_TB_REMOVE_CACHE = 9, UC_CTL_IO_WRITE = 1;
    int control = UC_CTL_TB_REMOVE_CACHE | (2 << 26) | (UC_CTL_IO_WRITE << 30);
    _error = uc_ctl2_ulong(_uc, control, begin, end);   // nouveau P/Invoke uc_ctl à 2 args u64
    return _error == UCErrors.Ok;
}
```

Portée : c'est un **bug de correction latent, indépendant du .NET** — il touche
aussi le malware natif auto-modifiant écrit via un chemin hôte. Le rendre correct
sert tout l'émulateur, pas seulement la Voie A. (`uc_mem_protect` ne flush pas non
plus : mêmes appels `remove_cache` sur les transitions de protection de pages déjà
exécutées.)

**Jambe KVM non testée ici** : pas de `/dev/kvm` dans l'environnement. Sur KVM le
SMC est natif (vrai CPU) donc a priori non problématique, mais **la jambe KVM du
J0 doit être rejouée sur un hôte KVM** pour clôturer le jalon.

Sous réserve du correctif ci-dessus, exécuter du code managé JIT-é est *le même
problème* que faire tourner un packer qui décompresse-puis-saute — chose que
Brovan fait déjà.

---

## 6. Inventaire des dépendances à fournir

### 6.a Dans `WindowsLibs/` (mappées par le loader guest)

- **Cible .NET Framework (recommandée en premier, cf. §10) :** `mscoree.dll`,
  `mscoreei.dll`, `clr.dll`, `clrjit.dll`, `mscorlib.dll`, + toute DLL VC++ dont
  clr dépend (déjà partiellement présentes). Bitness cohérent (x64 → pas de
  SysWOW64 ; x86 → `SysWOW64/` + **WOW64**, cf. Frontière F-WOW).
- **Cible .NET Core :** `hostfxr.dll`, `hostpolicy.dll`, `coreclr.dll`,
  `clrjit.dll`, `System.Private.CoreLib.dll`.

### 6.b Dans le VFS `VirtualFS/C/` (ouvertes par le CLR via `NtCreateFile`)

- **Framework :** l'arbre `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\` (ou
  `Framework\`) + le GAC (`C:\Windows\assembly\` / `Microsoft.NET\assembly\`)
  pour les assemblies de la BCL réellement touchées.
- **Core :** `Microsoft.NETCore.App/<ver>/` (les `System.*.dll` chargées) + les
  `*.runtimeconfig.json` / `*.deps.json` **à côté de l'image** (Brovan adosse
  déjà l'image dans le C: virtuel via `SeedGuestImageFile`, `WindowsGuest.cs:181`).

> **Provisioning = pattern établi.** `WindowsLibs` embarque déjà le runtime VC++
> réel et les tables NLS (`AL_KHASER_EMULATION.md`). Ajouter le runtime .NET est
> la même opération à plus grande échelle. Documenter le **hash/version** des
> binaires déposés (reproductibilité, règle « pas de valeurs magiques
> spécifiques à un échantillon »).

---

## 7. Points d'accroche précis dans le code

| # | Fichier / symbole | Modification |
|---|---|---|
| H1 | `Guests/WindowsGuest.cs::Initialize` (l.104) / `PrepareWinEnvironment` (l.1240) | Après mapping de l'image, si `Binary.PE.DotNetStatus == DotNet`, **basculer sur le chemin de bootstrap managé** au lieu de démarrer le thread sur l'entrypoint natif brut. |
| H2 | `WindowsGuest.cs::CreateInitialThread` (l.756) | Pour un .NET Framework legacy : le premier thread démarre déjà sur l'entrypoint = stub `_CorExeMain` ; il faut juste que l'import `mscoree` **résolve** (⇒ DLL présente). Pour .NET Core : la cible d'exécution est **l'apphost natif**, pas l'assembly managé — router vers l'apphost. |
| H3 | `WindowsLibs` + `GeneralHelper.cs::TryResolveFromWindowsLibs` (l.2924) | S'assurer que `mscoree.dll`/`clr.dll`/`clrjit.dll`/`coreclr.dll`/`hostfxr.dll`/… se résolvent (System32 + éventuellement chemins framework). |
| H4 | `Files/NtCreateSection.cs`, `Files/NtMapViewOfSection.cs` | Vérifier le mapping *image* (SEC_IMAGE) des grosses DLL runtime + de `System.Private.CoreLib.dll`. |
| H5 | `Process/NtProtectVirtualMemory.cs`, `Process/NtAllocateVirtualMemory.cs` | Chemin RW→RX du JIT (§5.2) ; propagation au backend + invalidation cache. |
| H6 | `BinaryEmulator.cs` hook `Syscall` (l.387) + `OS/Windows/**/Nt*.cs` | Compléter les syscalls que le bootstrap CLR exerce et qui manquent (§9). |
| H7 | `EmulationMenu` | Nouvelles commandes de diagnostic (ex. `dotnet run`, état du bootstrap CLR, dernière frontière atteinte). |
| H8 | Verdict/statut | Ne **jamais** router un échec de bootstrap CLR vers un statut « propre » factice : exposer honnêtement `[MISS]`/faute/dernier syscall (cohérent avec la discipline verdict d'Avroke). |

Aucun de ces points ne demande un « moteur MSIL » : ce sont des extensions du
chemin natif existant.

---

## 8. Plan d'implémentation par jalons (mesurable)

Format volontairement calqué sur la table de progression d'`AL_KHASER_EMULATION.md`
(instructions atteintes = métrique de progrès, terminus = état franchi).

| Jalon | But | Critère de réussite observable |
|---|---|---|
| **J0 — Spike JIT** ✅ **FAIT (GO, jambe Unicorn)** | Prouver que le backend exécute du code écrit puis exécuté à l'exécution, avec bascule RW→RX. | **Fait** via `scripts/jit_spike_j0.py` sur Unicorn 2.1.4 : 5/5 tests JIT-critiques verts (§5.d). **Correctif pré-requis identifié** : `remove_cache` sur écritures hôte de code (§5.d). **Reste** : rejouer la jambe **KVM** sur un hôte `/dev/kvm`. |
| **J1 — Provisioning** 🟡 **partiel** | Déposer le runtime cible dans `WindowsLibs` + framework dans le VFS ; résolution de chemins OK. | Le loader guest mappe `clr.dll`/`clrjit.dll` (ou `coreclr.dll`) sans `STATUS_DLL_NOT_FOUND` ; modules visibles dans la LDR list. **Mesuré (§8bis)** : Brovan **construit et tourne sur hôte Linux**, émule un PE natif de bout en bout ; mais le bundle deps ne contient **aucun runtime CLR** → à ajouter. Un publish **self-contained** (runtime app-local) est mappé et exécuté par l'apphost. |
| **J2 — Bind d'entrée** ✅ **FAIT (.NET Core)** | .NET Framework : l'import `mscoree!_CorExeMain` bind. .NET Core : l'apphost natif résout son chemin et charge la chaîne host. | **Mesuré (§8bis.2)** : après le fix `NtQueryFullAttributesFile`, l'apphost self-contained résout `pal::realpath` puis charge **`hostfxr.dll` → `hostpolicy.dll` → `coreclr.dll`**. |
| **J3 — Survie init CLR** 🟡 **profondément avancé** | Le CLR initialise GC/TLS/heaps sans faute non gérée. | **Mesuré (§8bis.2)** : le blocage 2 To est **corrigé** (réservation `SEC_RESERVE` sparse) → `coreclr_initialize` passe la réservation GC, commit/utilise le heap regions, et l'init tourne **~28 M instructions** (×4,7). **Nouvelle frontière** : fail-fast **`0xC0000005`** (AV interne coreclr) plus loin dans l'init, avant le 1er JIT (`clrjit` pas encore chargé). |
| **J4 — Première méthode JIT-ée** | `clrjit` compile et exécute au moins une méthode managée. | Bascule RW→RX observée + exécution du code produit ; RIP dans une page JIT. |
| **J5 — `Main()` managé** | Exécution du point d'entrée managé. | Effet de bord observable d'un `Console.WriteLine("...")` capté par `NtWriteFile`/console. |
| **J6 — Terminaison propre** | Sortie via l'`ExitProcess` du CLR. | Statut de sortie honnête ; trace syscalls exploitable. |
| **J7 — Robustesse** | Étendre au-delà du « hello world » (exceptions managées, threads, P/Invoke, réseau). | Un corpus de petits managés variés atteint J5/J6. |

Chaque jalon documente le **dernier syscall/instruction atteint** (comme la
table al-khaser) pour reprise sans re-analyse.

---

## 8bis. Résultats empiriques (build + run sur hôte Linux, 2026-07-17)

Première exécution réelle de bout en bout : Brovan **construit et lancé sur un
hôte Linux x86-64** (sans Windows, sans `/dev/kvm`), avec les vraies dépendances
Windows + Unicorn 2.1.4. Objectif : mesurer où en est concrètement la Voie A.

### Environnement (reproductible)

- **SDK .NET 8.0.423** requis. ⚠️ Le SDK apt `dotnet-sdk-8.0` (8.0.129, Roslyn
  **4.8**) **ne compile pas** Brovan : `Brovan.Generators` référence
  `Microsoft.CodeAnalysis.CSharp 4.10`, d'où `CS9057` → les 3 source-generators
  (`VulkanForwardGenerator`, `WinRegistryGenerator`, `StructSerializerGenerator`)
  ne s'exécutent pas → 23 erreurs de symboles absents (`BvkMK`,
  `BrovVulkGenDispatch`, `WinDeviceRegistry`…). Fix : SDK à bande **≥ 8.0.4xx**
  (Roslyn ≥ 4.10), ex. via `dotnet-install.sh --channel 8.0`.
- **Unicorn 2.1.4** : le `.so` du package Python (`pip install unicorn==2.1.4`)
  est byte-identique à la cible du build ; on peut court-circuiter la compilation
  source (`Brovan.Unicorn.targets`) en pré-plaçant
  `libunicorn.so` dans `.cache/unicorn/build/`.
- **Dépendances Windows** : bundle `WindowsLibs/` (Win10 19044, 80 DLL x64 + 79
  x86 + 120 NLS) + `WinReg/` (5 hives), importées via `scripts/Import-BrovanDeps.sh`.
  **`SortDefault.nls` absent** (warning : comparaison insensible à la casse
  dégradée). **Aucun runtime CLR** dans le bundle (voir plus bas).
- Un `mingw-w64` fournit un PE natif témoin ; un `dotnet publish -r win-x64
  --self-contained` fournit un runtime .NET Core **complet en PE Windows**.

### Ce qui marche

| Cas | Résultat |
|---|---|
| **Démarrage Brovan** | OK — `libunicorn.so` chargé, ApiSetMap auto-généré, `--help` OK. |
| **PE natif x64** (`mingw`, `printf`+`GetCurrentProcessId`, `return 7`) | ✅ **émulation complète** : sortie stdout correcte, `GetCurrentProcessId → 11150` réaliste, exit propre. Valide tout le stack (loader ntdll, mapping des vraies DLL, syscalls, CRT). |

### La frontière .NET, mesurée

| Cas | Observation |
|---|---|
| **PE managé .NET Framework** (net48, x64) | Brovan **détecte .NET** puis affiche : *« doesn't currently support emulating .NET CIL instructions → treated as a normal PE »* → exécute l'entrypoint natif (stub `mscoree`). Le **loader ntdll bootstrappe** (centaines de syscalls) mais **stalle** : `mscoree`/`clr`/`clrjit` **absents du bundle** (J1 non provisionné). |
| **Self-contained .NET Core** (net8, `win-x64`, runtime app-local complet : `coreclr.dll`/`clrjit.dll`/`hostfxr.dll`/`hostpolicy.dll`/`System.Private.CoreLib.dll` + framework, 187 fichiers) | **1re passe** : l'apphost tourne ~6 M instructions, mappe 15 DLL système, mais **échoue à résoudre son propre chemin** (`CoreHostCurHostFindFailure` 0x80008085) — cause **diagnostiquée et corrigée**, voir §8bis.2. **Après fix** : charge `hostfxr`→`hostpolicy`→`coreclr` et atteint J3. |

> ⚠️ La lecture initiale « termine avant hostfxr, corrèle avec F-THREAD » était
> une **fausse piste** : la worker factory Win32 vue au terminus est le pool
> loader/CRT bénin, pas le blocage. La vraie cause est isolée en §8bis.2.

### Lecture

- Le **stack d'émulation est validé** : un vrai process Windows natif s'exécute
  intégralement. La Voie A ne bute pas sur le socle, mais sur les couches .NET.
- **J1** : le seul manque est le **provisioning du runtime CLR** (le bundle n'en
  contient pas). Le publish self-contained le fournit app-local et Brovan le
  mappe — la voie « fournir le vrai CLR » est mécaniquement ouverte.
- **J2/J3** : voir §8bis.2 — J2 franchi (chaîne host chargée), J3 atteint avec
  une frontière nette (réservation GC 2 To).

### 8bis.2 — Percée J2→J3 : un syscall manquant, puis la réservation GC

**Diagnostic J2 (méthode).** Le message guest exact
`Failed to resolve full path of the current executable [C:\Users\…\mgdcore.exe]`
est le libellé corehost de `CoreHostCurHostFindFailure` (**0x80008085**).
`GetModuleFileNameW` renvoyait le **bon** chemin ; c'est `pal::realpath` qui
échouait. La trace `[ENTRY]` (mode `debug`) montre la séquence
`GetFileAttributesExW → RtlDosPathNameToRelativeNtPathName_U → NtQueryFullAttributesFile`
suivie de **`Unimplemented syscall … STATUS_NOT_SUPPORTED`**.

**Cause racine.** Brovan implémentait `NtQueryAttributesFile` (0x3D) mais **pas
son jumeau `NtQueryFullAttributesFile`** — que `kernelbase!GetFileAttributesExW`
utilise. Sans lui, `GetFileAttributesExW` échoue sur **tout** chemin, donc
`pal::realpath` échoue et l'apphost abandonne avant de chercher `hostfxr`. Ce
n'était **ni F-THREAD ni un fichier manquant** : un seul syscall.

**Fix (livré).** `Core/Emulation/OS/Windows/Files/NtQueryFullAttributesFile.cs` —
calqué sur `NtQueryAttributesFile`, écrit `FILE_NETWORK_OPEN_INFORMATION` (0x38,
ajoute `AllocationSize`+`EndOfFile`). Auto-enregistré par `WinRegistryGenerator`
(numéro extrait du vrai stub ntdll). Non-régression : le PE natif témoin reste
identique. Aligné sur `IDEAS.md` #1 (« ajouter des syscalls »).

**Effet mesuré.** L'erreur passe de « Failed to resolve full path » à
**`Failed to create CoreCLR, HRESULT: 0x80070008`** : l'apphost charge désormais
`hostfxr.dll` → `hostpolicy.dll` → **`coreclr.dll`** (confirmé par les `Loaded …`)
et appelle `coreclr_initialize`. **J2 franchi, J3 atteint.**

**Blocage J3 #1 : la réservation GC 2 To — CORRIGÉ.** `coreclr_initialize`
échouait `0x80070008` (`ERROR_NOT_ENOUGH_MEMORY`). Diagnostic (log temporaire sur
le chemin `STATUS_NO_MEMORY`) : `NtCreateSection` avec **`Size = 0x20000000000`
(2 To)** — la réservation d'espace d'adressage du `global_region_allocator` du
GC .NET 8 (feature *regions*). Brovan la rejetait (`Size > uint.MaxValue`) et
`MapUniqueAddress` aurait alloué un buffer réel ; `System.GC.HeapHardLimit` ne
réduit **pas** cette réservation (intrinsèque au GC regions).

**Fix (livré).** Le modèle mémoire de Brovan supporte déjà les réservations
paresseuses : `ReserveMemory` n'inscrit que des **métadonnées** (pas de
`uc_mem_map`), et `CommitMemory` mappe seulement les pages committées à la demande.
Le fix exploite ça : nouveau `ReserveSparseSection(Size, Protect)`
(`BinaryEmulator.WindowsBridge.cs`) qui réserve une grosse plage (>4 Go) en
métadonnées à une **base haute** (16 To), sans backing. `NtCreateSection` route les
sections non-image `Size > uint.MaxValue` vers ce chemin (au lieu de rejeter) ;
`NtMapViewOfSection` **saute le `uc_mem_protect`** sur la vue sparse (mémoire non
committée) et renvoie la base réservée ; les commits ultérieurs
(`NtAllocateVirtualMemory(MEM_COMMIT)` → `CommitMemory`) mappent page par page.
**Gate étroit** : seul le cas `Size > uint.MaxValue` — qui échouait déjà — change,
donc **zéro régression** sur les sections ≤4 Go (PE natif témoin identique).

**Effet mesuré.** Plus de rejet 2 To : `coreclr_initialize` réserve, commit et
**utilise** le heap regions, et l'init progresse de **6 M → ~28 M instructions**
(×4,7) avant la frontière suivante.

**Blocage J3 #2 (nouveau, diagnostiqué, non corrigé).** À ~28 M instructions,
coreclr fait un **fail-fast `NtTerminateProcess(0xC0000005)`** — une AV interne
qu'il attrape lui-même, **avant** le premier JIT (`clrjit` pas encore chargé). Le
syscall win32u **`0x1037`** non implémenté vu très tôt (ligne 862/66267, init CRT)
est **incident** et sans rapport. Trouver l'accès fautif racine (instruction /
adresse) est le **prochain pas concret** pour J4 : candidats — une valeur de
syscall que coreclr n'attend pas, une arête du modèle mémoire (TLS / heap
exécutable JIT), ou un chemin d'init exigeant plus de fidélité. NB : le .NET
**Framework** (heap CLR classique, sans regions 2 To) reste une piste alternative
une fois son runtime provisionné.

### Reproduction

```bash
# 1. SDK avec Roslyn >= 4.10
curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 8.0 --install-dir ~/.dotnet-new
export DOTNET_ROOT=~/.dotnet-new PATH="$HOME/.dotnet-new:$PATH"
# 2. Unicorn 2.1.4 (court-circuit du build source)
pip install unicorn==2.1.4
mkdir -p Brovan/.cache/unicorn/{unicorn-2.1.4,build}; : > Brovan/.cache/unicorn/unicorn-2.1.4.tar.gz
echo '#' > Brovan/.cache/unicorn/unicorn-2.1.4/CMakeLists.txt
cp "$(python3 -c 'import unicorn,os;print(os.path.dirname(unicorn.__file__))')/lib/libunicorn.so.2" Brovan/.cache/unicorn/build/libunicorn.so
# 3. Build + deps
dotnet build Brovan/Brovan.csproj -c Release
OUT=Brovan/bin/Release/net8.0
bash scripts/Import-BrovanDeps.sh -a BrovanDeps.zip -d "$OUT"
# 4. Run (LD_LIBRARY_PATH pour libunicorn.so app-local)
cd "$OUT" && LD_LIBRARY_PATH="$PWD" dotnet Brovan.dll --quick -s /path/to/sample.exe
```

---

## 9. Surface syscall probablement à compléter

Le bootstrap CLR est gourmand en primitives mémoire, threading, TLS et
exceptions. À auditer/compléter (beaucoup existent déjà) :

- **Mémoire / sections :** `NtAllocateVirtualMemory(Ex)`, `NtProtectVirtualMemory`,
  `NtFreeVirtualMemory`, `NtQueryVirtualMemory`, `NtCreateSection`,
  `NtMapViewOfSection`, `NtUnmapViewOfSection`, write-watch
  (`NtGetWriteWatch`/`NtResetWriteWatch`) — pierre angulaire du GC.
- **Threads / TLS / sync :** `NtCreateThreadEx`, `NtContinue(Ex)`,
  `NtSetInformationThread`, TEB slots / `TlsBitmap`, worker factory
  (`NtCreateWorkerFactory` déjà présent) — le CLR crée le finalizer thread + le
  thread pool tôt. ⚠️ voir le **bug scheduler MLFQ** signalé dans `IDEAS.md`
  (apps multi-thread qui sortent) : à traiter, le CLR est multi-thread par
  nature.
- **Exceptions :** dispatch SEH/VEH x64 (`.pdata`/`.xdata`) — le CLR pose des
  handlers très tôt ; cf. `docs/SEH_WER_DISPATCH_INVESTIGATION.md`.
- **Fichiers / config :** `NtCreateFile`/`NtOpenFile`/`NtReadFile`/`NtQuery*File`
  pour lire assemblies BCL + (Core) `*.runtimeconfig.json`/`*.deps.json`.
- **Divers :** horloges/perf counters, `NtQuerySystemInformation`, registre
  (clés .NET Framework sous `HKLM\SOFTWARE\Microsoft\.NETFramework`).

Méthode : lancer, observer le premier `[MISS]`/faute, implémenter, recommencer —
la boucle exacte qui a fait progresser al-khaser de 37 k à 24 M d'instructions.

---

## 10. Cible recommandée en premier

**Recommandation : .NET Framework 4.x, en x64, comme premier jalon** — mais à
**confirmer par le spike J0/J1** (esprit « les métriques sont des signaux »).

Raisons :

- chaîne de bootstrap **plus courte et self-contained** (§3.a) : pas de
  résolution hostfxr/hostpolicy + JSON avant de démarrer le runtime ;
- entrypoint **classique** (`_CorExeMain`), donc J2 est net ;
- x64 d'abord pour **éviter WOW64** (Brovan n'implémente pas WOW64, cf. Frontière
  F-WOW et `AL_KHASER_EMULATION.md` : « al-khaser x86 ne tourne pas ») ; les
  assemblies AnyCPU s'exécutent en x64 sur un OS x64.

.NET Core/5+ vient **ensuite** : plus représentatif du malware .NET moderne, mais
il faut d'abord faire survivre hostfxr/hostpolicy (résolution de framework,
parsing `.deps.json`/`.runtimeconfig.json`, TPA list) avant même coreclr. Le
gros de l'effort runtime (JIT, GC, EH) est commun aux deux cibles, donc l'ordre
n'est qu'une question de *quelle enveloppe de bootstrap* attaquer en premier.

---

## 11. Risques & frontières honnêtes

- **F-JIT — SMC + churn de retraduction (Unicorn).** SMC guest **validé au J0**
  (§5.d) ; correction seulement à ajouter pour les écritures **hôte** de code
  (`remove_cache`, §5.d). Reste un risque de **lenteur** si une vague de JIT
  retraduit beaucoup : mesurer sur cas réel, envisager KVM pour les runs lourds,
  ajuster le buffer TCG. Rejouer la jambe **KVM** du J0 sur un hôte `/dev/kvm`.
- **F-PERF — lenteur globale.** JIT + GC à travers un émulateur d'instructions =
  ordres de grandeur plus lent qu'un vrai process. Acceptable pour l'analyse ;
  à borner par les budgets d'instructions/temps existants.
- **F-WOW — pas de WOW64.** Les assemblies **x86** (ou marquées 32-bit-required)
  nécessitent WOW64, absent. Rester **x64/AnyCPU** tant que WOW64 n'est pas
  traité. C'est une frontière connue et documentée côté al-khaser.
- **F-THREAD — scheduler MLFQ.** Bug connu (`IDEAS.md`) sur le multi-thread ; le
  CLR est intrinsèquement multi-thread (finalizer, thread pool). Probable
  prérequis à J4+. *(NB : la worker factory vue au J2 avant le fix §8bis.2
  n'était **pas** ce bug — fausse piste ; le blocage réel était un syscall
  manquant. F-THREAD n'a donc pas encore été atteint empiriquement.)*
- **F-GCRESERVE — réservation d'espace d'adressage >4 Go — ✅ RÉSOLU.**
  Le GC regions .NET 8 réserve ~2 To via `NtCreateSection`/`SEC_RESERVE`.
  Corrigé par `ReserveSparseSection` (réserve métadonnées à base haute, commit à la
  demande) ; gate étroit sur `Size > uint.MaxValue`, zéro régression. `coreclr_initialize`
  franchit désormais la réservation (§8bis.2).
- **F-CLRINIT-AV — AV interne coreclr à ~28 M instructions (frontière J3/J4 active).**
  Après la réservation GC, `coreclr_initialize` fait un fail-fast
  `NtTerminateProcess(0xC0000005)` avant le 1er JIT. Cause racine non encore
  isolée (accès fautif à tracer). Bloque J4 (§8bis.2).
- **F-FRAMEWORK — surface BCL réelle.** Selon ce que l'assembly touche, le CLR
  charge de plus en plus d'assemblies système ⇒ plus de fichiers VFS + plus de
  syscalls. La couverture croît avec le corpus, pas d'un coup.
- **F-VERSION — couplage build.** clr/coreclr sont sensibles à la version de
  Windows annoncée (`WindowsVersionInfo` dans le PEB) et à leurs propres
  dépendances. Épingler des versions cohérentes de runtime et documenter les
  hash.
- **F-SINGLEFILE — bundles.** Publish single-file / self-contained (extraction
  de bundle, `apphost` embarquant le payload) : hors périmètre du premier jalon.
- **F-DÉTECTION — furtivité.** Un malware .NET peut sonder l'environnement CLR
  (versions runtime, chemins framework, présence du debugger managé). La
  cohérence doit s'étendre au runtime managé, pas seulement au natif (règle
  « ne pas être détecté »).

---

## 12. Critères de succès & tests

- **Fonctionnel :** un « hello world » managé (Framework puis Core) atteint J5
  (effet observable) puis J6 (sortie propre), les deux backends.
- **Non-régression :** aucun impact sur le chemin natif existant (le branchement
  H1 est gardé par `DotNetStatus == DotNet`).
- **Verdict honnête :** un échec de bootstrap reste un `[MISS]`/faute traçable,
  jamais un faux « propre » (H8).
- **Repro :** documenter les binaires runtime déposés (version + hash) et les
  fichiers VFS, comme la section *Reproduction* d'`AL_KHASER_EMULATION.md`.
- **Diagnostic :** commande menu affichant la dernière frontière de bootstrap
  atteinte + le dernier syscall, pour piloter l'itération J-par-J.

---

## 13. Repli : Voie B (interpréteur CIL)

Si la Voie A bute durablement (F-JIT/F-PERF/F-THREAD rédhibitoires), le repli est
un **interpréteur CIL dédié** consommant les métadonnées + l'IL **déjà extraits**
(`BinaryFile.cs:1719`), avec des shims BCL, façon `MSIL/` d'Avroke.Emulator
(~65 shims / 1500+ API). C'est un **moteur séparé** (pas la philosophie
real-DLL de Brovan) et un modèle de fidélité **différent** (on émule le
comportement de la BCL, pas le vrai framework), mais bien plus tractable pour
livrer vite de l'analyse comportementale. Les deux voies **partagent** le versant
statique existant et peuvent coexister (statique maintenant, dynamique ensuite).
Détail hors périmètre de ce document.

---

## 14. Interaction avec l'existant — à ne pas casser

- Le versant **statique** (§2) reste inchangé et sert de base aux deux voies.
- Le branchement runtime (H1) est **strictement gardé** par
  `DotNetStatus == DotNet` : un PE natif suit exactement le chemin actuel.
- Provisioning runtime = **extension** de `WindowsLibs`/VFS, pas de code hôte
  spécifique à un échantillon (règles « genericité » et « pas de valeurs
  magiques »).
- Toute nouvelle branche de terminaison respecte la **discipline de verdict** :
  honnêteté sur les frontières (H8).
