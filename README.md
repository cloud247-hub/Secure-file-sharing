# Cloud247 Secure File Sharing

Ende-til-ende-kryptert fildeling med statisk frontend og Cloudflare Worker/R2 backend.

## Arkitektur

1. Frontend krypterer filen lokalt med AES-256-GCM.
2. Kun den krypterte `.c247`-pakken sendes til Worker.
3. Worker lagrer pakken i R2 under en tilfeldig 24-tegns ID.
4. Delingslenken inneholder fil-ID og, i enkel nøkkelmodus, dekrypteringsnøkkelen i URL-fragmentet (`#...`).
5. Mottakeren henter kryptert data fra R2 og dekrypterer lokalt i nettleseren.

## Retention

Brukeren kan velge 30 minutter, 1 time eller 3 timer. Worker avviser utløpte objekter umiddelbart ved HEAD/GET, og en Cron Trigger rydder utløpte objekter fra R2 hvert 30. minutt.

## Sikkerhetsmodell

- AES-256-GCM i nettleseren
- tilfeldig 256-bit nøkkel eller PBKDF2-SHA256-passordmodus
- nøkkelen sendes aldri til Worker/R2
- filnavn og innholdsmetadata ligger inne i den krypterte pakken
- R2 lagrer kun kryptert innhold + teknisk retention-metadata
- ingen fillisting i API-et
- tilfeldig 144-bit fil-ID (24 base64url-tegn)
