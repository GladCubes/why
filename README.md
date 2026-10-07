# why

*Perche' questa porta e' aperta? Da dove arriva questa variabile?* `why` ricostruisce la catena e **mostra la prova di ogni passaggio**.

```
$ why port 25565
PORTA 25565
└── processo docker-proxy (pid 3173, utente root)  ← tiene aperto il socket in /proc/3173/fd
    ├── ascolta su: tcp 10.0.35.2:25565            ← tabelle /proc/net/*
    ├── inoltra al contenitore 172.18.0.2:25565    ← argomenti di docker-proxy
    │   └── contenitore 4301460e… (immagine ghcr.io/pterodactyl/yolks:java_25)  ← docker inspect: stesso IP
    ├── servizio systemd: docker.service           ← cgroup di /proc/3173/cgroup
    └── ≈ ip daddr 10.0.35.2 tcp dport 25565 dnat to 172.18.0.2:25565  ← nft list ruleset
```

## Comandi

| comando | cosa ricostruisce |
|---|---|
| `why port <N>` | chi ascolta, comando e cartella, chi lo ha avviato (tmux, systemd, contenitore), la unit con lo script che la lancia, i file di configurazione che nominano la porta, regole nft e porte pubblicate da Docker/Podman |
| `why env <NOME>` | il valore attuale e tutte le definizioni trovate: file della shell (bash, zsh, fish), `/etc`, `environment.d`, `.env` e `docker-compose` nelle cartelle sopra la tua |

## Come leggere l'output

- riga normale: **letto direttamente** dal sistema
- `≈` riga: **corrispondenza di testo**, probabile ma non dimostrata
- `?` riga: **non sono riuscito a verificarlo** (permessi, comando mancante, nessun risultato)

Se non sa, lo scrive. I valori che sembrano segreti (`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASS*`, password dentro una URL) non vengono mostrati.

Per vedere i processi di altri utenti e il firewall serve `sudo`. `why` **legge soltanto**: non modifica nulla.

## Stato

Linux (letto da `/proc`). Windows e `why package` / `why compare` sono i passi successivi. Nessuna dipendenza esterna.

```
cargo build --release                                    # binario normale
cargo build --release --target x86_64-unknown-linux-musl # statico, gira su qualunque distro
```

Licenza MIT.
