# MVP · StoreAMO Verify

## Resultado que debe entregar
Dado catálogo + artefacto/evidencia, producir un reporte reproducible que explique por qué una release puede o no usar el sello StoreAMO Verified.

## Gates mínimos
- L0 catálogo/schema;
- L1 SHA-256;
- L2 package/version/identidad;
- L3 firma/certificado cuando aplique;
- L4 permisos/política;
- L5 tests/evidencia del proyecto.

## Criterios obligatorios
- PASS/FAIL/SKIP/INFO diferenciados;
- SKIP nunca equivale a PASS;
- no necesita claves privadas;
- no ejecuta el artefacto;
- reporte referencia exactamente release/hash analizados;
- política de verificación es versionada.

## Fuera del MVP
- prometer ausencia de bugs;
- firmar artefactos.
