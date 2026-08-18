# Cloud247 Secure File Sharing v2

Ende-til-ende-kryptert fildeling med statisk frontend og Cloudflare Worker/R2 backend.

## Arkitektur

1. Frontend krypterer filen lokalt med AES-256-GCM.
2. Kun den krypterte `.c247`-pakken sendes til Worker.
3. Worker lagrer pakken i R2 under en tilfeldig 24-tegns ID.
4. Delingslenken inneholder fil-ID og, i enkel nøkkelmodus, dekrypteringsnøkkelen i URL-fragmentet (`#...`).
5. Mottakeren henter kryptert data fra R2 og dekrypterer lokalt i nettleseren.

## Mapper

- `frontend/` — GitHub Pages-app for `securefile.cloud247.no`
- `worker/` — Cloudflare Worker + R2 backend for `securefile-api.cloud247.no`

## 1. Deploy Worker

```bash
cd worker
npm install
npx wrangler login
npx wrangler r2 bucket create cloud247-secure-files
npm run deploy
```

`wrangler.jsonc` oppretter Worker Custom Domain `securefile-api.cloud247.no` ved deploy. Cloudflare krever at dette hostname ikke allerede har en CNAME-record.

## 2. Deploy frontend

Last opp innholdet i `frontend/` til repository-roten og aktiver GitHub Pages. `CNAME` er satt til:

```text
securefile.cloud247.no
```

Frontend bruker som standard:

```text
https://securefile-api.cloud247.no
```

Endre `frontend/config.js` og `worker/wrangler.jsonc` hvis du bruker andre hostnavn.

## Retention

Brukeren kan velge 1 time, 24 timer eller 7 dager. Worker avviser utløpte objekter umiddelbart ved HEAD/GET, og en Cron Trigger rydder utløpte objekter fra R2 hvert 30. minutt.

## Sikkerhetsmodell

- AES-256-GCM i nettleseren
- tilfeldig 256-bit nøkkel eller PBKDF2-SHA256-passordmodus
- nøkkelen sendes aldri til Worker/R2
- filnavn og innholdsmetadata ligger inne i den krypterte pakken
- R2 lagrer kun kryptert innhold + teknisk retention-metadata
- ingen fillisting i API-et
- tilfeldig 144-bit fil-ID (24 base64url-tegn)

### Viktig om offentlig drift

Tjenesten tar imot anonyme krypterte blobs. Serveren kan derfor ikke innholdsskanne filene. Legg til Cloudflare Rate Limiting/WAF før bred offentlig lansering, bruk korte retention-tider og følg med på lagringsbruk.

«Slett etter første henting» sletter objektet når første GET når Worker. R2-sletting er sterk konsistent etter at slettingen er fullført, men to helt samtidige GET-er kan rekke å hente objektet før slettingen. Bruk en Durable Object hvis du trenger strengt atomisk engangsforbruk.
