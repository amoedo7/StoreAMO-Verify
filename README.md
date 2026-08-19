<div align="center">

# StoreAMO Verify

**Evidencia antes de mostrar “Verificado”.**

`SHA-256` · `package/version` · `firma` · `permisos` · `CI evidence`

</div>

---

StoreAMO Verify existe para evitar que el catálogo confíe ciegamente en nombres, descripciones o archivos subidos.

La verificación se organiza por niveles:

```text
L0 · catálogo válido
L1 · integridad SHA-256
L2 · identidad del artefacto
L3 · firma / certificado
L4 · permisos y política
L5 · evidencia de tests del proyecto
```

Una aplicación puede estar publicada como `development` o `candidate` sin pasar todos los niveles. Sólo una release con evidencia suficiente puede marcarse `verified`.

## Qué significa “StoreAMO Verified”

Significa que los controles declarados para esa release pasaron y existe un reporte reproducible. **No significa “software sin bugs”.**

## Uso rápido

Validar el contrato básico del catálogo:

```bash
python verify_catalog.py ../StoreAMO-Catalog/catalog.json
```

Verificar un artefacto local contra una entrada del catálogo:

```bash
python verify_catalog.py catalog.json --app midispositivo --platform android --artifact MiDispositivo.apk
```

Si el artefacto es Android y están disponibles `aapt`/`aapt2` y `apksigner`, el verificador intentará extraer información adicional sin fallar por no tener esas herramientas instaladas.

## Seguridad

- no necesita claves privadas;
- no contiene tokens GitHub;
- no firma artefactos;
- no ejecuta el APK;
- no descarga binarios salvo que el pipeline que lo use lo haga explícitamente;
- el reporte separa `PASS`, `FAIL`, `SKIP` y `INFO`.

---

**DesarrollAMO** · StoreAMO verifica evidencia, no promesas.