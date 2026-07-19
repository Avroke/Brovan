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
| **J3 — Survie init CLR** ✅ **FAIT** | Le CLR initialise GC/TLS/heaps sans faute non gérée. | **Mesuré (§8bis.2-3)** : trois blocages corrigés — réserve GC 2 To (sparse), gros reserve VirtualAlloc (espace haut), **modèle de pile** (réserve+garde) — plus le contournement W^X (`DOTNET_EnableWriteXorExecute=0`). `coreclr_initialize` **réussit**. |
| **J4 — Première méthode JIT-ée** ✅ **ATTEINT** | `clrjit` compile et exécute au moins une méthode managée. | **Mesuré (§8bis.3-4, binaire frais + commande `start`)** : chaîne host complète `apphost→hostfxr→hostpolicy→coreclr→clrjit` (toute la narration `COREHOST_TRACE` visible grâce au fix console-device), **`clrjit.dll` chargé**, ~**158 M instructions** de code managé JIT-é. Terminus : exception managée non gérée `0xE0434352` **avant `Main`** → frontière J5. |
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

**Blocage J3 #2 : le double-mapping W^X — ROOT CAUSE ISOLÉE.** À ~28 M
instructions coreclr fait un fail-fast `NtTerminateProcess(0xC0000005)`. Le hook
mémoire de Brovan donne l'accès fautif racine :
`write (protected) addr=0x100000000010 rip=coreclr+0x172373`. Diagnostics
temporaires (dump région à la faute + attributs section/vue) :

- La section 2 To est `SEC_RESERVE`, `prot=PAGE_EXECUTE_READWRITE`.
- coreclr en mappe **deux vues à la même base** (`0x100000000000`), l'une RWX, l'autre RW.
- La page fautive est `committed=True prot=PAGE_EXECUTE_READ` : coreclr **écrit** sur une page **RX**.

C'est le **`ExecutableAllocator` double-mappé (W^X) de coreclr** : il mappe la même
section à **deux adresses** — une vue **RX** (exécution) et une vue **RW** (écriture
du code JIT) partageant le stockage. Le `NtMapViewOfSection` de Brovan renvoie la
**même base** pour les deux → elles se collapsent, et l'écriture via la « vue RW »
tombe sur la page RX → faute. Émuler l'aliasing mémoire (2 VA, 1 backing) est très
dur sous Unicorn (`uc_mem_map` alloue un backing hôte distinct par plage).

**Le contournement propre : désactiver W^X.** `DOTNET_EnableWriteXorExecute=0`
(variable d'env guest) fait basculer coreclr sur un mapping **unique RWX** pour le
code — pas de double-map, pas d'aliasing — exactement ce que le modèle mémoire de
Brovan supporte (et que le spike J0 a validé). **Mesuré** : le double-map disparaît
(0 faute), coreclr progresse plus loin, révélant la **chaîne** de gaps mémoire du
mode W^X-off :

1. Le code allocator réserve alors de grosses plages via `VirtualAlloc(MEM_RESERVE,
   base=NULL)` → `FindFreeBaseAddress` de Brovan (fenêtre ~128 Go) échoue.
   **Corrigé (livré)** : `FindFreeBaseAddress` route les réserves >16 Go vers
   l'espace sparse haut (pendant du fix section ; `NtAllocateVirtualMemory{,Ex}`).
2. Frontière suivante : commit d'une **page de garde de pile**
   (`Base≈0x1017B000 size=0x5000 prot=PAGE_GUARD|PAGE_READWRITE`) sur une région
   non-réservée → `CommitMemory` refuse. À traiter ensuite.

**Voie recommandée pour J4-J5** : intégrer proprement `DOTNET_EnableWriteXorExecute=0`
(injection d'env guest, idéalement gated sur détection .NET), puis dérouler la
chaîne W^X-off (page de garde, etc.). Alternative de fond : émuler le vrai
double-mapping (aliasing 2 VA/1 backing) — beaucoup plus lourd. NB : le .NET
**Framework** (heap CLR classique, sans regions 2 To ni W^X double-map par défaut)
reste une piste alternative une fois son runtime provisionné.

**Évaluation stratégique (honnête).** La chaîne W^X-off est une **longue traîne de
changements mémoire substantiels**, pas des correctifs incrémentaux : (1) gros
reserve VirtualAlloc — *fait* ; (2) **modèle de pile** réserve+garde (F-STACKGUARD)
— substantiel, touche toutes les piles ; (3) très probablement d'autres arêtes
après (TLS managé, heap exécutable, EH). Atteindre **J4/J5** est réaliste mais
c'est un **effort multi-PR** ciblé, chaque étape tracée + testée isolément pour ne
pas régresser le chemin natif validé. Les deux fixes mémoire déjà livrés
(sparse-section, gros-reserve) sont génériques et bénéficient à tout l'émulateur ;
la suite (stack model) l'est aussi. Décision d'investissement à prendre avant de
poursuivre : dérouler la chaîne W^X-off, ou provisionner un runtime **.NET
Framework** (chaîne plus courte, sans regions/double-map) pour un chemin J3-J5
potentiellement plus direct.

### 8bis.3 — Percée J3→J4 : modèle de pile fidèle → JIT chargé, code managé exécuté

La chaîne W^X-off a été déroulée jusqu'à **J4**. Après le contournement W^X
(`DOTNET_EnableWriteXorExecute=0`, intégré dans l'env guest) et le fix gros-reserve,
la frontière **F-STACKGUARD** a été **corrigée** :

**Root cause (mesurée).** Les diagnostics montrent que coreclr commit une garde de
pile à `StackLimit - 0x5000` (ex. `0x1017B000`, juste sous la pile à `0x10180000`),
et que `AllocateThreadStack` = `MapUniqueAddress` mappait la pile en **un seul bloc
committé sans rien en dessous** ⇒ le commit de garde tombait sur du non-mappé.
Appelants confirmés `clr!…` (mise en place de la garde de pile de coreclr).

**Fix (livré).** `AllocateThreadStack` modélise la pile à la Windows :
**réserve** `[base, base+taille+headroom)`, **commit** seulement la pile utile en
haut, laissant un **headroom réservé** (1 MiB) sous `StackLimit`. Le commit de
garde du guest passe alors par le chemin reserve→commit de `CommitMemory`. Gate :
la pile utile vue par le guest est **inchangée** (RSP toujours dans
`[StackLimit, StackBase)`), fallback sur l'ancien mapping si le placement échoue —
**PE natif témoin identique** (non-régression vérifiée).

**Résultat mesuré.** `coreclr_initialize` **réussit**, puis **`clrjit.dll` +
`System.Private.CoreLib.dll` sont chargés** et **~116 M instructions** (×4 vs 28 M)
de code managé JIT-é s'exécutent. **J3 franchi, J4 atteint.**

**Nouvelle frontière J5 (managée).** coreclr **attrape** une exception managée à
~116 M instructions et sort via `NtTerminateProcess(0xE0434352)` (code SEH CLR),
**sans message imprimé** — fail-fast pendant l'init runtime managée, **avant `Main`**.
Bisection : un `Main` réduit à `return 5` (sans `Console`) throw **au même point** →
l'exception est **indépendante du corps de `Main`** (init runtime/CoreLib).
Diagnostic mené : `NtOpenEvent` (0x40) + `NtCreateNamedPipeFile` (0xB4)
**implémentés** (livrés) — l'exception **persiste**, donc écartés. Elle ne passe pas
par le syscall `NtRaiseException` (dispatch **user-mode** `RtlDispatchException`), d'où
l'absence de signal côté hook syscall. **Prochain pas** : intercepter le dispatch
d'exception user-mode (ou marcher la TLS Thread de coreclr) pour lire le type/message,
et/ou identifier les classes des **8× `NtQueryInformationProcess → NOT_SUPPORTED`** —
pour atteindre **J5** (`Main` managé + sortie observable).

### 8bis.4 — Deux corrections méthodo (SDK + commande `run` vs `start`), console-device fix validé, J5 reconfirmé

Cette section corrige deux **erreurs de méthode** commises en cours de session, puis
reconfirme le blocage J5 avec la bonne procédure.

**⚠️ Piège n°1 — SDK de build.** Dans cet environnement, `/usr/bin/dotnet` est le SDK
**8.0.129** (Roslyn 4.8) qui **ne peut pas** compiler `Brovan.Generators` (source
generator Roslyn ≥ 4.10) : le build **échoue silencieusement** si l'on masque la sortie
(`-v q | tail`), et l'exit code observé vient du `tail`, pas de `dotnet` — laissant en
place un **binaire périmé**. **SDK correct : `/root/.dotnet-new/dotnet` (8.0.423)**.
Toujours vérifier le vrai exit code (`${PIPESTATUS[0]}`) + le mtime du `Brovan.dll`.

**⚠️ Piège n°2 — commande du menu : `run` ≠ `start`.** En mode `--quick` **sans** `-s`,
le menu démarre sans thread initial. La commande **`run`** (→ `RunMlfqScheduler`) crée
alors un thread via `CreateEmulatedThread(IP)` dont le **contexte initial est incomplet**
pour un vrai démarrage de processus Windows : le loader ntdll tourne mais **l'entrée de
l'image ne s'exécute jamais** (0 ligne `[ENTRY]` / `[CFT]` depuis l'EXE, ~5,77 M instr,
`ret` au sentinel). La commande **`start`** (`Emulator.Start()`) démarre correctement le
thread initial via `RtlUserThreadStart` → entrée. **Toute mesure de bring-up .NET/natif
doit passer par `start`** (ou le mode `-s`), jamais par `run` sur un binaire fraîchement
chargé. (L'ancienne lecture « retour-au-sentinel à 5,77 M / deadlock thread » était
**entièrement** un artefact du piège n°2 — il n'y a ni deadlock ni retour-avant-`Main`.)

**Blocage J5 reconfirmé (mesuré, binaire frais + `start` + staging Desktop original).**
La chaîne host s'exécute **intégralement et correctement** :
`apphost → resolve fxr → hostfxr_main_startupinfo → hostpolicy → deps.json (self-contained,
TPA complet) → coreclr.dll → clrjit.dll` (**J4**), puis ~**158 M instructions** de code
managé JIT-é, terminus **`NtTerminateProcess(0xE0434352)`** (exception managée CLR non
gérée pendant l'init runtime, **avant `Main`** — inchangé avec un `Main` réduit à
`return 5`). C'est donc bien la frontière **F-CLRMANAGED** de §8bis.3, pas un blocage de
threading.

**Le fix console-device est validé de façon décisive.** Avec `COREHOST_TRACE=1` dans
l'env guest, **toute** la narration hostfxr/hostpolicy devient **visible** (elle sort par
`WriteFile(stderr)` sur un handle console que l'ancien `NtWriteFile` jetait) :
`--- Invoked apphost [8.0.29]`, `Resolved fxr […hostfxr.dll]`,
`Executing as a self-contained app`, `CoreCLR path = […coreclr.dll]`,
`Launch host: …mgdcore.dll`, `--- End breadcrumb write 1` (dernier log avant
`coreclr_execute_assembly`). Sans le fix, **zéro** de ces lignes n'apparaissait. C'est
l'outil de diagnostic décisif pour la suite (activer `COREHOST_TRACE=1` à la demande ;
laissé **désactivé par défaut** pour ne pas polluer les traces de malwares).

**Livré cette session.**
1. **Fix console-device** (`NtWriteFile`) : une écriture vers un handle console **autre
   que `STD_OUT`** (celui que `NtCreateFile` rend pour `CONOUT$`/`\Device\ConDrv`, =
   `ConsoleHandle`) tombait sur la branche Device → `STATUS_INVALID_DEVICE_REQUEST` →
   **texte jeté**. Désormais routée vers la console comme `STD_OUT`. Générique + validé
   ci-dessus (trace host visible, message d'exception managé futur visible).
2. **Diagnostics de cycle de vie des threads** (gated `LogFlags.General`) : retour-au-
   sentinel (+ `last-slice-rip`), mort en slice via exception, `TryTerminateThread`, dump
   des threads parqués en fin de scheduler — ce sont eux qui ont permis d'isoler le piège
   n°2 (RIP de retour résolu à `RtlUserThreadStart` ntdll `0x52630`).

**Prochain pas J5.** L'exception managée ne s'imprime pas (fail-fast avant le reporting
d'exception non gérée). Deux pistes : (a) l'exécuter avec un coreclr **checked**
(`DOTNET_LogEnable`/stress-log) OU capter le message via le reporting managé (maintenant
que la console est routée) ; (b) instrumenter les **8× `NtQueryInformationProcess →
NOT_SUPPORTED`** pour identifier les classes qu'une API CoreLib d'init interroge. La
**voie Framework** (mscoree→clr) partage le finalizer/thread-pool et buterait sans doute
sur une frontière voisine ; pas un raccourci.

### 8bis.5 — Percée J5 (couche 1) : `BadImageFormatException` root-causé + corrigé (mapping SEC_IMAGE des assemblies managés)

**Lecture de l'exception.** Un diagnostic ajouté au chokepoint `[ENTRY]` : à l'entrée du
filtre SEH top-level du CRT (`ucrtbase!_seh_filter_exe(ULONG code, PEXCEPTION_POINTERS)`,
x64 : RCX=code, **RDX=pointeurs**), on lit l'`EXCEPTION_RECORD` et on mappe l'adresse de
levée à un module. Résultat :
`code=0xE0434352 raised @ KERNELBASE+0x34F99 (RaiseException) params=[ 0x800700C1 … coreclr_base ]`.
`param[0] = 0x800700C1 = HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT)` ⇒ **`BadImageFormatException`**.

**Root cause (mesurée).** Deux `NtMapViewOfSection → STATUS_INVALID_IMAGE_FORMAT`
(0xC000007B → ERROR_BAD_EXE_FORMAT → 0x800700C1) juste après « Loaded mgdcore.dll ». Cause :
`NtMapViewOfSection` rejetait le mapping **SEC_IMAGE** dès que `Image.Architecture !=`
l'arch du processus. Or un assembly **managé AnyCPU / IL-only** porte `Machine = I386`
(donc `Architecture` = x86) même sur x64 — la bitness réelle est décidée par les CorFlags,
pas le champ Machine. coreclr mappe les assemblies runtime en `SEC_IMAGE` ; le rejet
remontait en `BadImageFormatException` fatale.

**Fix (livré).** Dans `NtMapViewOfSection`, ne plus imposer l'égalité d'architecture pour
une **image managée** (`Image.PE.DotNetStatus != None`) : on n'exige la correspondance
d'arch que pour les images **natives** (un DLL natif x86 dans un processus x64 reste
correctement refusé). Narrowly-scoped : le natif est inchangé par construction.

**Résultat.** Le `BadImageFormatException` **disparaît**. coreclr progresse plus loin —
il **spawn désormais des threads** (init multi-thread : un thread se termine proprement
`status 0x0`, deux autres actifs) — puis bute sur la **couche suivante** :
`code=0xE0434352 … param[0] = 0x80070057 = E_INVALIDARG`. Exception managée générique
(vraisemblablement un `ArgumentException`/`E_INVALIDARG` dans l'init CoreLib), **non**
liée à un syscall en échec (les syscalls voisins sont `NtAllocateVirtualMemory` = GC, tous
SUCCESS). C'est la nouvelle frontière J5.

**Diagnostic livré (permanent, gated `LogFlags.General`) :** le dump `[SEH-FILTER]`
(code + adresse de levée→module + params). C'est l'outil qui a pelé la couche 1 ; il
rendra lisible chaque couche suivante (l'HRESULT dans `param[0]` identifie la classe
d'exception managée).

**Couche 2 (E_INVALIDARG) — RÉSOLUE.** Le diagnostic `[SEH-FILTER]` a été étendu en
`[COMPLUS-STACK]` (marche la pile capturée du `ContextRecord` du filtre — les frames de
levée sont encore vivantes avant unwind — et mappe chaque adresse retour à `module+rva`).
Avec les **PDB publics coreclr 8.0.29 + ntdll** (symbol server) et `llvm-symbolizer`, la
chaîne s'est symbolisée sans ambiguïté : `coreclr_execute_assembly → CorHost2::ExecuteAssembly
→ … → EEFileLoadException::Throw` avec `hr = HRESULT_FROM_GetLastError()`. En sondant la
levée C++ réelle (`_CxxThrowException` → `RaiseException(0xE06D7363)`, dont le `ThrowInfo →
CatchableType → TypeDescriptor` porte le nom de type C++), l'exception est un
**`EEFileLoadException`** levé depuis `AppDomain::TryIncrementalLoad → Assembly::Create →
LoadedImageLayout` (`peimagelayout.cpp:527` : `CLRLoadLibraryEx(path, NULL, …)`). La
`LoadLibraryExW` en échec (via un hook entrée+sortie) : **`System.Runtime.dll`** — un
**façade de type-forwarding PE32/I386/ILONLY** — retournait `NULL`/`ERROR_INVALID_PARAMETER`.
Cause racine : `BinaryEmulator.LoadWinLibrary` **rejetait** l'image managée AnyCPU (`Machine =
I386 ≠ hôte x64`) avec « non-valid PE library », alors que le CLR JIT-e l'IL vers l'archi
hôte — real Windows charge une image ILONLY quel que soit le champ `Machine`. **Fix** :
`LoadWinLibrary` n'applique désormais le contrôle d'archi qu'aux images **natives**
(`!IsManagedLibrary`), en miroir du gate `NtMapViewOfSection` (§8bis.5). Aucun patch du champ
`Machine` mappé n'est nécessaire (vérifié : le loader ntdll accepte l'image I386-mappée telle
quelle ; réécrire `Machine → AMD64` tout en laissant `Magic = PE32` créait une incohérence
que le PEDecoder de coreclr rejetait plus loin en `0x80070002`). En parallèle, un vrai bug de
`NtFreeVirtualMemory` a été corrigé : `MEM_RELEASE` avec `RegionSize != 0` est une **release
partielle** (le syscall découpe la réservation et garde le reste), pas une erreur — la règle
« RegionSize doit valoir 0 » appartient au wrapper Win32 `VirtualFree`, pas au syscall
(`RtlpSecMemFreeVirtualMemory` de ntdll et le loader over-reserve-puis-release-l'excès via le
syscall direct) ; ajout d'un `ReleaseMemoryRange` fidèle (split-et-drop-du-milieu).

**Résultat mesuré** : `System.Runtime.dll` se charge (`handle=0x400000`), l'exception
`E_INVALIDARG` disparaît, et la voie Core **avance jusqu'à la frontière F-THREAD** : coreclr
démarre son threading runtime complet (`.NET Finalizer`, `loader worker`, thread-pool via
`NtCreateThreadEx`/`NtResumeThread`) puis **bute sur le mur de threading coopératif** — des
threads parkent indéfiniment sur un event (`0x8C`, `deadline=-1`), le scheduler termine avec
4 threads en `Waiting` + un `0xC0000005` sur un worker. C'est **exactement la même frontière
F-THREAD** que la voie Framework (§8bis.6) : le hand-off loader/CLR multi-thread. Régression
native vérifiée nulle (`hello_native.exe` : init CRT → `fputc` → `exit`, propre).

**F-THREAD, couche 1 — pelée : réveil worker-factory sur release.** En symbolisant les RIP
de park via les PDB ntdll, la frontière s'est disséquée : le thread principal (7977) spinne
dans `ZwWaitForAlertByThreadId` (le primitif derrière `WaitOnAddress` / SRW / `Lock`/`Monitor`
.NET), tandis que les workers du thread-pool parkent dans `ZwWaitForWorkViaWorkerFactory`
(deadline INFINITE). Cause : **`NtReleaseWorkerFactoryWorker` enfilait bien le travail dans la
file de complétion de la factory, mais ne réveillait aucun worker déjà parké** — `EnsureWorkerThreads`
ne *crée* que de nouveaux threads, il ne réveille pas les existants. Le worker restait donc
bloqué indéfiniment, le travail relâché ne s'exécutait jamais, et le rendez-vous du thread-pool
ne se faisait pas. **Fix** : `WakeWorkerFactoryWaitersForFactory` réveille un worker parké pour
la factory (il re-exécute son wait, dépile la release, exécute le travail) — appelé depuis
`NtReleaseWorkerFactoryWorker` après `EnqueueReleaseCompletion`. Comportement fidèle à Windows
(une release réveille un worker), étroit (ne se déclenche que sur le chemin worker-factory,
donc zéro effet sur les samples natifs), validé sans régression native.

**Effet mesuré** : la voie Core **initialise désormais le runtime .NET complètement** — les
threads `.NET Finalizer` (idle sur un `Sleep(Timeout.Infinite)`) et `.NET Tiered Compilation
Worker` (poll 1 s) apparaissent, preuve que le startup runtime va bien plus loin qu'avant (il
deadlockait avant même leur création). Il reste **une couche F-THREAD** : le thread principal
reste bloqué sur l'event auto-reset `0x8C` (créé par lui-même via `NtCreateEvent`, `eventType=1`),
un rendez-vous final qu'un thread de fond doit signaler. Émettre plus de comportement (plus de
threads, syscalls, grams) est un gain net pour l'analyse comportementale, même sans atteindre
`Main`. Prochaine couche : tracer le signaleur de `0x8C` (probablement le thread pool /
DiagnosticServer une fois son propre wait satisfait).

### 8bis.6 — Voie Framework (.NET Framework 4.x, CLR classique) : provisionnée, le shim bootstrappe

En parallèle de la voie **Core** (coreclr, self-contained), la voie **Framework** exécute
un PE managé net4x via le **CLR classique OS** : `mscoree → mscoreei → clr → clrjit →
mscorlib → Main`. État livré : **provisionnée jusqu'au bootstrap du shim** ; frontière =
un spin de synchro thread dans l'init du shim.

**Le blocage `mscoree.dll` + le pont mscoreei.** Un net4x x64 importe
`mscoree.dll!_CorExeMain` ; sans le fichier, le loader guest termine sur
**`0xC0000135` (STATUS_DLL_NOT_FOUND)** à ~91 k instr. Or `mscoree.dll` est un composant
**Windows OS** (System32) — il n'est **ni** dans les deps fournies **ni** dans
l'installeur .NET (qui ne livre que `mscoreei.dll`). **Résolution** : sur Windows moderne
`mscoree.dll` est un stub qui **forwarde vers `mscoreei.dll`** — lequel exporte toute la
surface requise (`_CorExeMain` / `_CorExeMain2` / `_CorDllMain` / `CorExitProcess` /
`CLRCreateInstance`, 125 exports). On **stage `mscoreei.dll` en tant que
`WindowsLibs/mscoree.dll`** (pont). Mesuré : l'import résout, **`Loaded MSCOREE.DLL`**, et
le shim **bootstrappe** (KERNEL32/KERNELBASE/ADVAPI32/RPCRT4, port CSR `NtConnectPort`,
`NtInitializeNlsFiles`, accès registre) — plus de DLL_NOT_FOUND.

**Provisioning livré (committable).**
1. **`scripts/Import-FrameworkRuntime.sh`** : stage `clr.dll` / `clrjit.dll` /
   `mscoreei.dll` / `mscorlib.dll` (+ `mscordacwks` / `mscordbi` / `mscorrc` /
   `mscorsecimpl`, amd64 4.0.15744.551) dans le VFS guest
   `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\`, et pose le pont
   `WindowsLibs\mscoree.dll ← mscoreei.dll`. Source = payload de l'installeur .NET 4.8
   (`ndp48-*.exe`) expansé (WinSxS `amd64_netfx4-*`).
2. **Clés registre de découverte du runtime** (seedées en code, `WinSyscallsHelper.cs`) :
   `HKLM\SOFTWARE\Microsoft\.NETFramework\InstallRoot` = `…\Framework64\`,
   `…\policy\v4.0`, `NET Framework Setup\NDP\v4\{Full,Client}` (`Install`=1,
   `Release`=528040, `Version`=`4.8.04084`, `InstallPath`). Sans elles le shim ne peut
   localiser `clr.dll`.

**Frontière (spin de synchro à l'init du shim) — diagnostic précis.** Après le bootstrap,
le thread principal (mesuré : tid 21435) crée les events et un thread worker (tid 9024),
puis **spin `NtSetEvent`** en boucle serrée **sans jamais bloquer**, tandis que le worker
se parque sur un **unique `NtWaitForSingleObject` (PENDING, deadline infinie)** et n'est
jamais ré-ordonnancé. `clr.dll` n'est pas encore chargé. Les diagnostics ajoutés
(`[NEW-EVENT]` / `[WAIT-PARK]` / `[SET-EVENT]`, gated `LogFlags.General`) donnent le détail
exact :

- le worker (9024) parque sur l'event **`0x4C`** (type 0 = **NotificationEvent /
  manual-reset**, `initialState=False`), créé par le main ; c'est son event « travail
  disponible ». Il n'est **jamais** signalé de tout le run.
- le main (21435) **signale en boucle `0x90` et `0x8C`** (type 1 = auto-reset), tous deux
  avec **`waitersOnThisHandle=0`** — donc des events **différents** de `0x4C`.

Autrement dit le main pousse du travail au loader/worker mais **signale les mauvais events**
(ou l'objet de synchro que Brovan modélise ne correspond pas à celui que le worker attend) :
`0x4C` reste orphelin → 9024 dort → le main spin dans son drain. Les events ne sont **pas**
aliasés à tort (`NtCreateEvent` passe `null` comme nom ⇒ chaque anonyme est bien distinct) ;
le problème est la **livraison du travail** (comme le worker-factory de la voie Core, ici
via un event manuel plutôt qu'`NtWaitForWorkViaWorkerFactory`). Un
`NtSetEvent → RequestSchedulerWakeupScan` (tenté puis **reverté** : ne résout pas ce cas —
le waiter n'attend pas l'event signalé — et non-régression non vérifiable) ne suffit pas.

**Localisation à l'instruction (stack-walk `[SET-EVENT-SPIN]`).** Après 20 000
`NtSetEvent` consécutifs sur le même thread, un stack-walk mappe les adresses de retour aux
modules : la boucle est dans **`mscoreei.dll` (0xECE0/0xED12)**, un **thunk de résolution
paresseuse par ordinal** — il compare un pointeur global à lui-même, sinon appelle
`KERNEL32!GetProcAddress(hModule, 0x8E)` (= **ordinal 142**), cache le résultat, puis
`call rbx` (la fonction résolue, qui fait le `SetEvent`). Stack ntdll associée :
`LdrGetProcedureAddressForCaller`, `RtlAllocateHeap`, `RtlInitializeCriticalSection`.
C'est donc un **hand-off loader/CLR** : mscoreei résout/appelle des fonctions runtime par
ordinal pendant que le worker loader (9024) dort sur `0x4C`. **Le fix précis** exige soit
les **symboles PDB mscoreei** (nommer la fonction ordinal-142 + la condition de boucle),
soit un trace complet d'une itération — au-delà du tractable de façon fiable sans risquer
un changement scheduler/loader spéculatif (interdit faute de pouvoir lancer la suite de
tests Brovan). Le détecteur `[SET-EVENT-SPIN]` (stack-walk d'un thread qui signale en
boucle) est livré comme outil permanent (gated `LogFlags.General`).

**Bilan.** La voie Framework est **provisionnée et le CLR classique démarre son shim** ;
elle **partage** la frontière de threading coopératif de la voie Core, donc — comme
anticipé — **pas un raccourci vers `Main`**. Test : `dotnet Brovan.dll <net4x-x64.exe>`
puis commande **`start`** (cf. piège n°2 §8bis.4).

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
# 3. Build + deps  (IMPÉRATIF: SDK 8.0.4xx / Roslyn >= 4.10 — le SDK apt 8.0.129
#    échoue SILENCIEUSEMENT sur Brovan.Generators et laisse un binaire périmé)
~/.dotnet-new/dotnet build Brovan/Brovan.csproj -c Release
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
  Le GC regions / code allocator réserve ~2 To (via `NtCreateSection`/`SEC_RESERVE`
  **et** via `VirtualAlloc(MEM_RESERVE, base=NULL)`). Corrigé par
  `ReserveSparseSection` (sections) **+** la branche « espace haut » de
  `FindFreeBaseAddress` (`NtAllocateVirtualMemory{,Ex}`) : réserve métadonnées à
  base haute (16 To), commit à la demande. Gate étroit (>uint.MaxValue / >16 Go),
  zéro régression (§8bis.2).
- **F-WXMAP — double-mapping W^X du code coreclr (frontière J3/J4 active).**
  Root cause du fail-fast `0xC0000005` : coreclr mappe sa section de code à **deux
  VA** (RX exécution + RW écriture, backing partagé) ; Brovan renvoie la même base
  → collision → l'écriture tombe sur la page RX. Contournement propre mesuré :
  `DOTNET_EnableWriteXorExecute=0` (mapping unique RWX). Émuler le vrai aliasing
  2 VA/1 backing sous Unicorn est l'alternative lourde (§8bis.2).
- **F-STACKGUARD — modèle de pile réserve+garde — ✅ RÉSOLU.** coreclr committait une
  garde à `StackLimit - 0x5000` sur du non-mappé car `AllocateThreadStack` mappait la
  pile en un seul bloc committé. Corrigé : `AllocateThreadStack` **réserve** la pile
  + un headroom (1 MiB) et ne **commit** que le haut, laissant le bas réservé pour la
  garde du guest (chemin reserve→commit de `CommitMemory`). Pile utile inchangée pour
  le natif ; débloque le chargement de `clrjit` + l'exécution managée (§8bis.3).
- **F-CLRMANAGED — ✅ J5 ATTEINT (managé `Main` exécuté, valeur de retour observée).**
  Historique : la chaîne host s'exécute **intégralement**
  (`apphost→hostfxr→hostpolicy→coreclr→clrjit→System.Private.CoreLib→System.Runtime`, **J4**),
  puis le managé JIT-é. **Couche 1 pelée (§8bis.5)** : `[SEH-FILTER]` a identifié un
  `BadImageFormatException` (`0x800700C1`), root-causé au rejet du mapping `SEC_IMAGE` des
  assemblies managés AnyCPU (`Machine=I386`) par `NtMapViewOfSection` — **corrigé**. **Couche 2 :**
  `E_INVALIDARG` (`0x80070057`) au chargement des façades ILONLY AnyCPU — `LoadWinLibrary`
  rejetait le mismatch d'architecture ; **corrigé** (accepte les images managées malgré
  l'arch). **Couche 3 (threading, F-THREAD) :** le pool de threads .NET / loader parallèle
  se coordonne via worker-factory + événements ; `NtReleaseWorkerFactoryWorker` n'éveillait
  pas un worker déjà parké — **corrigé** (`WakeWorkerFactoryWaitersForFactory`). **Couche 4
  (staging) :** un échantillon .NET Core auto-contenu stagé sous le VFS était aplati sur un
  Desktop synthétique, séparé de son runtime coreclr —
  l'apphost échouait à `hostfxr` (« application does not exist ») avant coreclr ; **corrigé**
  (reverse-map du chemin hôte VFS → chemin lecteur invité, runtime co-localisé). **Résultat :**
  managé `Main` (`class P { static int Main() { return 5; } }`) s'exécute et le thread principal
  se termine avec le code de sortie **`0x5`** — **J5 franchi**, aucune exception `0xE0434352`
  avant `Main`.
- **F-CLRINIT-AV — déterminisme de J5 : use-after-free du tas CRT → AV `RtlAllocateHeap` → deadlock loader — ✅ RÉSOLU.**
  Avant correctif : J5 **fiable dans le cas commun mais non déterministe** (~**1/22** runs deadlockaient tôt,
  ~19 M instr, le reste propre à ~110,35 M). **Après correctif : 105/105 runs propres, 0 faute** (deux batchs
  45 + 60 ; baseline ~4-5 fautes attendues, P(0|non-corrigé) < 1 %) + régression native intacte
  (`hello_native` : sortie propre, 1,97 M instr). **J5 est désormais déterministe.** **Cause racine symbolisée** (llvm-symbolizer + PDB Microsoft) : sur le run
  qui deadlocke, l'instruction fautante `ntdll!RtlAllocateHeap+0x2A9C0` est `cmp [rbx+0x10], 0xDDEEDDEE`
  (lecture de la **signature `_SEGMENT_HEAP`**) avec `rbx=rcx=HeapHandle` **corrompu** → **ce n'est pas
  une corruption de free-list mais un `HeapHandle` invalide passé à `RtlAllocateHeap`**. Chaîne d'appel
  symbolisée du fautif : `ADVAPI32 → SHELL32 → ucrtbase/msvcrt!_calloc_impl → RtlAllocateHeap` — c.-à-d.
  **`_calloc_impl` alloue depuis le `_crtheap` de msvcrt**, dont le handle (`0x100310000` / `0x100420000`
  selon le run) tombe dans une région que **Brovan a libérée** (classifieur `[FREE-TRACK]`/`IsRegionFreed`
  → `[freed-region: use-after-free]`). **Root cause = use-after-free du tas CRT** : le `[FREE-TRACK]`
  identifie le libérateur comme **`coreclr!GCToOSInterface::VirtualRelease` depuis `WKS::gc_heap::initialize_gc`**
  (la sonde de dimensionnement du GC réserve puis relâche une région, ex. `[0x100270000, 0x100320000)`)
  **qui recouvre le `_crtheap` vivant** de msvcrt à `0x100310000`. La bande VA `0x1_00xxxxxx` est partagée
  et brassée par les `MEM_RELEASE` partiels de `RtlCreateHeap` (→ `RtlpSecMemFreeVirtualMemory` →
  `ReleaseMemoryRange`) **et** la sonde GC : occasionnellement (~1/22, dépend de l'ordre d'allocation donc
  de l'ordonnancement) une allocation vivante (le `_crtheap`) se retrouve dans une plage qu'une autre
  sous-système relâche, et l'unmap tue le tas CRT. **Mécanisme exact confirmé** : `ReleaseMemoryRange`
  copiait le `MemoryRegion` entier pour construire les pièces survivantes Left/Right d'une relâche
  partielle → une survivante **héritait l'`AllocationBase` d'origine**. Sur le motif over-reserve de
  `RtlCreateHeap` (réserve large, aligne la base vers le haut, relâche l'excès-avant), le tas survit comme
  pièce supérieure mais gardait l'`AllocationBase` de la **base de réservation désormais libérée** ; une
  réservation ultérieure réutilisant cette base libérée (la sonde GC) partage alors la même
  `AllocationBase`, et `ReleaseMemory(base)` regroupe **les deux** régions par `AllocationBase`
  (`End = max` sur le groupe) et unmap le tas CRT vivant.
  **Correctif** (`ReleaseMemoryRange`, commit `8cdefeb`) : quand la plage relâchée couvre l'ancre d'une
  région (`AllocationBase ∈ [Start,End)`), **ré-ancrer chaque pièce survivante sur sa propre base**. Le
  tas survivant devient une allocation indépendante dont l'`AllocationBase` = son handle, donc une base-avant
  réutilisée ne peut plus le regrouper dans une relâche étrangère ; corrige aussi
  `RtlDestroyHeap(heapBase)` et le `AllocationBase` remonté par `VirtualQuery` pour ces tas. Quand l'ancre
  n'est PAS libérée (elle survit ailleurs), l'`AllocationBase` d'origine est préservée → une vraie relâche
  d'allocation entière atteint toujours chaque pièce (pas de fuite).
  **Diagnostics livrés** (tous poussés, réutilisables) : classifieur de faute freed/decommitted/never-mapped
  (`ClassifyFaultAddress`), dump registres+chaîne d'appelants (`DumpFaultCallStack`/`[FAULT-CTX]`),
  traceur de libération avec appelant guest dans la bande CRT (`[FREE-TRACK]`), `[CLR-AV]`. PDB
  coreclr/clrjit/ntdll/msvcrt + chaîne llvm-symbolizer validés. **`NtTerminateProcess(NULL)`**
  (reap des threads de fond au shutdown) est **corrigé** en amont : **validé bout-en-bout** sur un run
  où l'AV n'a pas fauté — `Main` retourne 5, `RtlExitUserProcess` → `NtTerminateProcess(NULL,5)` reape
  le finalizer + les workers (`STATUS_SUCCESS`, plus d'`ACCESS_DENIED`), self-terminate, puis
  **`Scheduler finished: no live threads`** à ~110 M instructions. Avant ce correctif, le meilleur cas
  atteignait `Exit(5)` mais spinnait sur les threads runtime orphelins ; désormais le processus se
  termine proprement. Reste donc uniquement le **déterminisme** (l'AV non-déterministe ci-dessus) pour
  un J5 fiable à 100 %.
- **F-CONSOLE-MANAGED — `System.Console` managé via ConDrv (frontière active, sortie observable).**
  Le J5 trivial (`Main` = `return 5`) est déterministe (F-CLRINIT-AV résolu). Un programme managé plus
  riche (`Console.WriteLine` + `for`/`List`/LINQ) **charge bien `System.Console.dll` + `System.Linq.dll`,
  exécute ~140 M instructions**, mais **lève une `ArgumentOutOfRangeException` non gérée
  (`0xE0434352`, hr `0x80131502`) au fond de l'init de `System.Console`** → terminaison `0xE0434352`.
  Diagnostic (trace `[CONDRV-API]` ajoutée puis retirée) : le CRT natif imprime via `NtWriteFile` direct
  (OK — cf. `hello_native`), **mais `System.Console` de .NET Core dialogue avec `\Device\ConDrv` par
  `NtDeviceIoControlFile(IoctlConDrvIssueUserIo)`** et le `ConsoleServer` reçoit un **`ApiNumber` parasite**
  (une valeur pointeur, l'offset `0x28` du header ne correspond pas au `CONSOLE_API_MSG` de ce build) **et
  un `OutputBuffer` vide (`outLen=0`)** → `HandleIssueUserIo` sort par la garde de buffer vide sans servir
  la requête → `GetConsoleOutputCP`/`GetConsoleScreenBufferInfo` renvoient 0/garbage → l'init `Console`
  jette. **C'est un chantier ConDrv à part** (protocole `CONSOLE_API_MSG` + acheminement des buffers
  METHOD_NEITHER par `NtDeviceIoControlFile`, offsets du header, mécanisme de réponse), pas un stub isolé.
  Le milestone J5 (atteindre `Main` managé, déterministe) reste **acquis** ; la sortie console managée est
  la prochaine étape.
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
