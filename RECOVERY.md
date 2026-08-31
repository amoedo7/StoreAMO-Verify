# StoreAMO-Verify recovery

## Objetivo

Recuperar esta unidad de verificación de forma reversible sin otorgarle autoridad de publicación, firma o instalación.

## Fuente de verdad

La recuperación parte de `main` y de una revisión Git conocida. El repositorio conserva código y controles; no conserva ni debe reconstruir claves privadas, tokens de publicación ni autoridad sobre StoreAMO o StoreAMO-Catalog.

## Procedimiento

1. Identificar la última revisión conocida como buena mediante Git/CI.
2. Crear una rama de recuperación desde esa revisión; no reescribir `main`.
3. Restaurar únicamente archivos propios de StoreAMO-Verify.
4. Ejecutar `bash scripts/autocheck.sh`.
5. Ejecutar el workflow de CI aplicable y conservar evidencia del SHA probado.
6. Integrar sólo mediante PR y sólo si los gates ejecutan realmente y terminan PASS.

## Límites

- No convertir `SKIP`, `UNKNOWN` ni un check no ejecutado en `PASS`.
- No firmar, publicar, instalar ni promover artefactos como parte de una recuperación.
- No introducir secretos ni material privado de firma.
- No modificar StoreAMO, StoreAMO-Catalog ni sus políticas desde esta unidad.
- No inferir que una release externa está verificada sólo porque este repositorio fue restaurado.

## Rollback

Si una recuperación empeora el estado o falla sus gates, abandonar/revertir la rama o PR y conservar `main` en la última revisión conocida como buena. Cualquier cambio cross-domain permanece bloqueado hasta sus gates externos correspondientes.
