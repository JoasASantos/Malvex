# Malware Analysis Skills

Este arquivo é o índice operacional das skills de análise de malware do Malvex.

Cada domínio da matriz fica em `skills/<dominio>/SKILL.md`. O objetivo não é gerar texto bonito. O objetivo é transformar hipótese em evidência verificável.

## Regras globais

- hypothesis -> evidence -> verification -> confidence
- LLM output != evidence
- similaridade técnica != atribuição
- renomear funções quando o comportamento for sustentado por xrefs, APIs, strings, CFG ou traço de runtime
- alegações de runtime exigem artefato: log, dump, trace, hook, captura ou alteração observável
- ATT&CK, family match, lineage e capability mapping são saídas derivadas; nunca substituem a prova primária

## Evidência mínima por finding

- locus exato: RVA, VA, offset, symbol, section, PID/base, path, key ou endpoint
- tipo de evidência: header, import, string, xref, pseudocode, disassembly, debugger trace, memory dump, file artifact, packet capture, config blob
- explicação curta do que foi observado
- confidence e gaps restantes

## Skills ativas — Triage & Initial Assessment (5)

| Skill | Foco |
| --- | --- |
| `triage-initial` | hashes, tipo real, arquitetura, assinatura, packer, entropia, strings e IOC surface |
| `entropy-packer-detect` | entropia por seção, assinaturas de packer/protector, inventário de shielding |
| `code-signing-analysis` | assinaturas digitais, Authenticode, codesign, cadeias de certificado |
| `resource-enumeration` | recursos embarcados em PE/ELF/MachO, payloads escondidos, ícones, manifests |
| `string-secret-extract` | extração de strings (plaintext, stack, cifradas, FLOSS), secrets, credenciais |

## Skills ativas — Static Analysis (8)

| Skill | Foco |
| --- | --- |
| `static-analysis` | headers, sections, imports/exports, resources, TLS, relocations, debug, manifest e runtime |
| `import-export-surface` | mapeamento completo de API surface, resolução dinâmica, API hashing |
| `library-dependency-map` | bibliotecas linkadas, versões, CVEs, identificação de compilador/linker |
| `algorithm-identification` | fingerprint de algoritmos criptográficos, modos, chaves, primitivas fracas |
| `hardcoded-crypto-blobs` | chaves, certificados, tokens e material secreto embarcado no binário |
| `embedded-blob-carve` | extração de payloads embarcados, blobs cifrados, binários secundários |
| `data-structure-recovery` | recuperação de estruturas internas, vtables, hierarquias de classes |
| `binary-diff-compare` | comparação de variantes, diff de patches, evolução de capabilities |

## Skills ativas — Decompilation & Code Analysis (3)

| Skill | Foco |
| --- | --- |
| `disassembly-decompilation` | função principal, CFG, call graph, xrefs, argumentos, API resolution |
| `symbol-recovery` | recuperação de nomes de funções/variáveis de binários stripped |
| `syscall-surface-map` | syscalls diretas/indiretas, evasão de EDR, interação de baixo nível com OS |

## Skills ativas — Packing & Obfuscation (2)

| Skill | Foco |
| --- | --- |
| `packing-obfuscation` | stub, OEP, unpacking, import rebuild, string crypto, API hashing, loaders |
| `emulation-unpacking` | unpacking baseado em emulação (Unicorn, Qiling, speakeasy) |

## Skills ativas — Dynamic Analysis (4)

| Skill | Foco |
| --- | --- |
| `dynamic-analysis` | processos, filesystem, registry, services, IPC, memória, discovery |
| `debugging` | breakpoints, argumentos, stack, heap, threads, exceptions, fluxo entre módulos |
| `process-injection` | injeção clássica, hollowing, APC, reflective, module stomping, syscall-based |
| `hook-detection` | hooks IAT, inline, EAT, VMT, SSDT, unhooking de EDR |

## Skills ativas — Memory & Forensics (3)

| Skill | Foco |
| --- | --- |
| `process-memory-analysis` | injeção, RWX, executable private memory, hollowing, config em memória |
| `memory-forensics` | dumps de memória, processos ocultos, módulos injetados, artefatos do kernel |
| `network-forensics` | análise de PCAP, reconstrução de protocolo, C2 traffic, exfiltração |

## Skills ativas — Network & C2 (3)

| Skill | Foco |
| --- | --- |
| `network-analysis` | DNS, IPs, URLs, HTTP(S), TLS, C2 patterns, beaconing, exfil, DGA |
| `command-and-control` | config C2, protocolo, tasking, auth, fallback, proxy, Tor, dead drops |
| `c2-protocol-analysis` | análise profunda de protocolo C2, beacon, DGA, criptografia, multiplexação |

## Skills ativas — Evasion & Anti-Analysis (3)

| Skill | Foco |
| --- | --- |
| `defense-evasion` | sandbox/VM/debugger checks, timing, LOTL, cleanup, masquerading |
| `anti-analysis` | PEB/debug checks, hardware/VM artifacts, timing, self-modifying code |
| `sandbox-evasion` | detecção de VM/sandbox, timing checks, interação de usuário, geofencing |

## Skills ativas — Persistence & Privilege (2)

| Skill | Foco |
| --- | --- |
| `persistence-analysis` | Run Keys, services, tasks, WMI, systemd, cron, LaunchAgents |
| `privilege-escalation` | tokens, UAC, services, drivers vulneráveis, impersonation |

## Skills ativas — Malware Family Analysis (9)

| Skill | Foco |
| --- | --- |
| `ransomware-analysis` | criptografia, gerenciamento de chaves, ransom notes, pagamento, recuperação |
| `shellcode-analysis` | decoder stubs, PIC, PEB walking, API hashing, egg hunters, staged payloads |
| `stealer-analysis` | credential harvesting, browser data, crypto wallets, clipboard hijacking |
| `bootkit-rootkit` | MBR/VBR/UEFI persistência, kernel hooks, DKOM, BYOVD |
| `fileless-malware` | PowerShell/WMI, registry payloads, LOLBins, reflective loading |
| `document-malware` | macros VBA/XLM, OLE exploits, PDF JavaScript, RTF, DDE, template injection |
| `wiper-analysis` | disk wiping, MFT destruction, backup deletion, propagação destrutiva |
| `cryptominer` | pool connections, algoritmo de mining, wallet addresses, resource management |
| `backdoor-analysis` | command dispatch, remote shell, file ops, surveillance, plugins |

## Skills ativas — Delivery & Propagation (3)

| Skill | Foco |
| --- | --- |
| `dropper-loader` | multi-stage delivery, download-and-execute, staged payload chains |
| `lateral-movement` | PsExec, WMI, WinRM, DCOM, credential relay, network propagation |
| `supply-chain-analysis` | dependency confusion, typosquatting, build pipeline, trojanized updates |

## Skills ativas — Configuration & Extraction (3)

| Skill | Foco |
| --- | --- |
| `malware-configuration` | campaign ID, bot ID, C2s, chaves, flags, build/version, mutex, beacon |
| `config-extraction` | extração e parsing de configuração embarcada, decriptação, estrutura |
| `credential-data-access` | browser data, cookies, tokens, wallets, SSH, cloud creds, keylogging |

## Skills ativas — Discovery & Targeting (2)

| Skill | Foco |
| --- | --- |
| `discovery-analysis` | OS, usuário, hostname, domínio, software, processos, VM, cloud |
| `exfiltration-analysis` | staging, archive, compression, encryption, destino, cleanup |

## Skills ativas — Detection Engineering (4)

| Skill | Foco |
| --- | --- |
| `detection-engineering` | YARA, Sigma, EDR logic, DNS/HTTP/TLS, memória, filesystem, registry |
| `yara-rule-generation` | geração de regras YARA para detecção, classificação e threat hunting |
| `sigma-rule-generation` | geração de regras Sigma para detecção comportamental |
| `ioc-extraction` | hashes, domains, IPs, URLs, paths, registry, mutexes, services, certs |

## Skills ativas — Threat Intelligence (4)

| Skill | Foco |
| --- | --- |
| `threat-intelligence` | família, variantes, code reuse, overlaps de infra/config/TTP |
| `malware-lineage` | function/CFG/call graph similarity, embeddings, árvore evolutiva |
| `capability-mapping` | funções e evidências em capabilities e ATT&CK com rastreabilidade |
| `apt-tooling` | implantes custom, LOTL, staged ops, infrastructure fingerprinting |

## Skills ativas — Specialized Targets (3)

| Skill | Foco |
| --- | --- |
| `mobile-malware` | Android/iOS: permissões, overlay, SMS intercept, accessibility abuse |
| `firmware-analysis` | firmware images, filesystem extraction, credentials, backdoor services |
| `ai-assisted-re` | function classification, renaming, decoder recognition, variant comparison |

## Como usar

- Comece por `triage-initial`.
- Se houver packing, entre em `packing-obfuscation` e `emulation-unpacking` antes de concluir `static-analysis`.
- Se houver execução real, `debugging`, `dynamic-analysis`, `process-memory-analysis` e `network-analysis` devem produzir evidência correlacionada.
- Use `config-extraction` cedo — configuração é o artefato de maior valor para threat-intel.
- Para ransomware, stealer, wiper, etc., use a skill de família correspondente.
- `shellcode-analysis` e `document-malware` cobrem vetores de entrega especializados.
- Toda função relevante deve sair com nome mais semântico quando houver prova suficiente.
- Ao final, `capability-mapping`, `ioc-extraction`, `detection-engineering` e `threat-intelligence` consolidam o valor operacional da análise.

## Perguntas finais que a plataforma deve responder

- What is it?
- What does it do?
- How does it do it?
- What does it target?
- How does it persist?
- How does it evade detection?
- Where does it communicate?
- What is the impact?
- How can we detect it?
- What evidence proves each conclusion?
