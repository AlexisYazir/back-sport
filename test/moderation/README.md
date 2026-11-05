# Moderacion: PostgreSQL y HTTP reales en una copia efimera

Ejecutar desde esta rama revisada, con Docker ya iniciado y las imagenes fijadas
en cache. No instala paquetes, descarga imagenes, compila EAS, carga `.env` ni
contacta Render, correo, pagos u otros proveedores.

PowerShell:

```powershell
$env:MODERATION_QA = 'true'
node test/moderation/run-isolated.cjs
Remove-Item Env:MODERATION_QA
```

Jest usa las dependencias Windows ya instaladas. El proceso recibe solo las
variables de sistema necesarias, tres URLs QA de la base, la bandera explicita y
la llave JWT sintetica; no hereda tokens ni credenciales de proveedores.

El runner verifica la imagen PostgreSQL por digest y una red privada exclusiva
del proyecto. Esta red no bloquea tecnicamente el egreso. Publica un
puerto aleatorio exclusivamente en `127.0.0.1` y comprueba el binding real de
Docker antes de conectar; rechaza exposicion en otras interfaces. PostgreSQL usa
tmpfs y un nombre de proyecto exclusivo evita tocar otros contenedores. No cambia
dependencias ni usa un runtime Linux adicional. Al terminar se destruye la
composicion y su puerto, incluso ante fallos.

Se usan controladores, fachada, DTO, ValidationPipe, estrategia JWT, sesiones,
guardas de rol/administrador activo, servicios de moderacion y repositorios
reales. Solo se excluyen las dependencias ajenas a esas rutas. Los JWT se firman
con una llave sintetica y consultan sesiones reales del fixture; no se acredita
el proceso de emision/login ni el AppModule completo.

La migracion TypeORM se ejecuta realmente con `synchronize:false`. El esquema
inicial minimo conserva las columnas previas de las entidades necesarias y datos
identificados como QA. No es una copia ni una certificacion del esquema de
produccion.

Se comprueban autorizacion401/403, administrador activo, rechazo de campos de
actor falsos, referencias de reporte, conservar/retirar/restaurar, conteos
publicos sin campos privados, revision409 y concurrencia, prohibicion de volver
a publicar una reseña retirada, historial inmutable, proteccion del folio y actor
de respuesta derivado del servidor. Un trigger temporal QA provoca un fallo de
auditoria para verificar rollback atomico. Se prueba up/down sin decisiones y
el rechazo de down cuando borraria datos de moderacion.

Solo `test-results/sportcenter-moderation-qa-<pid>/summary.json` es evidencia
compacta: estados, hashes y limpieza. Los diagnosticos sin sanear se conservan
localmente solo al fallar; no deben publicarse ni incorporarse al commit.

Un resultado aprobado acredita la implementacion aislada y sus transacciones.
No prueba despliegue, permisos o datos productivos, una persona atendiendo
reportes, correo enviado ni retirada de contenido real. No modifica la app
movil ni demuestra su aceptacion nativa.

Referencias: [Nest TestingModule](https://docs.nestjs.com/fundamentals/testing)
y [migraciones TypeORM](https://typeorm.io/docs/advanced-topics/migrations/).
El [binding de puertos Docker](https://docs.docker.com/engine/network/port-publishing/)
se comprueba realmente, sin asumir que el nombre de la red impida acceso externo.

## Orden para activar la moderacion

La rama parte de `1cac85d`, el commit previo de respuesta publica de registro y
correcciones de lint. Ese cambio debe revisarse como dependencia al integrar;
no forma parte del nuevo commit de moderacion preparado sobre esa base.

Antes de activar el backend nuevo, la persona autorizada debe respaldar la base,
validar sus permisos y aplicar la migracion versionada. El codigo nuevo consulta
las columnas `retirada` y `revision`, por lo que no debe arrancar sobre el esquema
anterior. El runner incluido aqui solo acepta QA; no es un comando de produccion.

Despues se comprueban el acceso Admin, la cola y conservar/retirar/restaurar con
datos autorizados. El panel depende de esas rutas y se activa despues. Las pruebas
locales no sustituyen esa comprobacion operativa ni autorizan un despliegue.

## Reversion y conservacion del historial

La migracion se niega a revertir si hay decisiones o reseñas retiradas. No se debe
borrar el historial ni cambiar su contenido para forzar una reversion.

Volver sin mas al backend anterior tambien es peligroso: sus consultas ignoran
`retirada` y volverian a mostrar contenido moderado. Cualquier reversion de codigo
debe conservar el filtro publico y la evidencia de las decisiones; ante un fallo,
se debe corregir esa version o suspender temporalmente la consulta afectada antes
que volver a publicar reseñas retiradas.
