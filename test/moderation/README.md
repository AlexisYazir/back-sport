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
del proyecto. Esta red no bloquea tecnicamente el egreso del contenedor.
Publica un puerto aleatorio exclusivamente en `127.0.0.1` y comprueba el
binding real de Docker antes de conectar; rechaza otras interfaces. Se comprueba
el contexto Docker local antes de crear recursos. PostgreSQL usa
tmpfs y un nombre de proyecto exclusivo evita tocar otros contenedores. No cambia
dependencias ni usa un runtime Linux adicional. Al terminar se destruye la
composicion y el puerto local, incluso ante fallos. El proceso Node de las pruebas
carga una guarda que rechaza conexiones TCP fuera del loopback numerico; esa
guarda es una defensa QA, no sustituye un sandbox del sistema operativo.

Se usan controladores, fachada, DTO, ValidationPipe, estrategia JWT, sesiones,
guardas de rol/administrador activo, servicios de moderacion y repositorios
reales. Solo se excluyen las dependencias ajenas a esas rutas. Los JWT se firman
con una llave sintetica y consultan sesiones reales del fixture; no se acredita
el proceso de emision/login ni el AppModule completo.

La migracion TypeORM se ejecuta realmente con `synchronize:false`. El esquema
inicial minimo conserva las columnas previas de las entidades necesarias y datos
identificados como QA. No es una copia ni una certificacion del esquema de
produccion. Los reportes se ubican explicitamente en `core.contact_messages`,
tanto en la entidad como en el SQL del servicio y la FK del historial. Antes
del primer ALTER, el preflight rechaza tablas ausentes o ambiguas en public,
columnas/tipos/PK incompatibles e instalaciones parciales. No mueve ni copia
tablas para adaptar una base desconocida.

Se comprueban autorizacion401/403, administrador activo, rechazo de campos de
actor falsos, referencias de reporte, conservar/retirar/restaurar, conteos
publicos sin campos privados, revision409 y concurrencia, prohibicion de volver
a publicar una reseña retirada, historial inmutable, proteccion del folio y actor
de respuesta derivado del servidor. Un trigger temporal QA provoca un fallo de
auditoria para verificar rollback atomico. Se prueba up/down sin decisiones y
el rechazo de down cuando borraria datos de moderacion.

El CLI QA se ejecuta como proceso Node real en la misma base efimera. Se comprueba
que un esquema invalido no crea siquiera el ledger, que un primer up valido
registra la migracion en `core.review_moderation_migrations` y que un segundo up
se rechaza sin cambios. Un ledger anterior o ambiguo tambien se rechaza antes de
DDL. La reversion por CLI con decisiones conserva historial y ledger.

`test-results/sportcenter-moderation-qa-<id>/summary.json` es evidencia compacta:
estados, hashes, hash del dump y limpieza. Los resultados detallados y el dump
sintetico se conservan localmente tambien al aprobar; pueden contener filas de
sesion QA y no deben publicarse ni incorporarse al commit. Se conserva cada
ejecucion, incluidos los fallos.

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
La factory de migracion QA exige `qa_admin`, una clave local no vacia, puerto
loopback explicito y la base dedicada `sportcenter_moderation_qa`, sin query ni
fragmento. Si el ledger de otro entorno ya contiene esta migracion, se debe
revisar su version efectiva antes de continuar; no se fuerza una reaplicacion.

El respaldo CRITICAL actual omite `core.contact_messages` y
`core.review_moderation_events`: no basta para preservar folios e historial.
Antes de una activacion autorizada se requiere un respaldo FULL y una restauracion
verificada en otra base, incluidos roles y privilegios, funciones, triggers,
secuencias y ledger. La restauracion debe comprobar los permisos SELECT que
correspondan sobre folios e historial. La migracion no concede SELECT a todos los
roles lectores; el dueño de la base debe definir y comprobar los grants
autorizados, incluidos roles heredados y cualquier politica RLS. La prueba con
`qa_admin` no certifica esos permisos de otro entorno.

La factory, el CLI y esta suite fijan el ledger en
`core.review_moderation_migrations`, independientemente del search_path. El CLI
hace preflight de solo lectura antes de que TypeORM pueda crear ese ledger.
Rechaza instalaciones parciales, entradas ya registradas o los nombres anteriores
en core/public; no interpreta una segunda ejecucion como un no-op aprobado.
Ante esos rechazos se revisa el esquema, la version y el ledger existente; no se
borran filas del ledger, se fuerza down ni se modifica el timestamp para continuar.
En el checkout fuente el CLI utiliza ts-node. La imagen incluye ese mismo
script y las clases compiladas en dist, por lo que no necesita dependencias
de desarrollo para ejecutar `npm run moderation:qa:status`,
`npm run moderation:qa:plan`, `npm run moderation:qa:up` o
`npm run moderation:qa:down`. Los dos primeros solo consultan y no crean el
ledger. Todos conservan las guardas QA: flags explicitos, loopback numerico,
qa_admin y sportcenter_moderation_qa; no son comandos para una base compartida.
El CLI QA conserva SSL desactivado en esa conexion local. Esto es independiente
de las conexiones TLS de main y no cambia su configuracion.

La imagen contiene los clientes PostgreSQL de Debian bookworm. Sus operaciones
se validan con PostgreSQL 15 QA; antes de activar backups en otro entorno, el
operador debe verificar version del servidor, version/ruta de pg_dump y psql,
permisos y restauracion. No se presume compatibilidad con una version Neon
que no se haya observado.

Despues se comprueban el acceso Admin, la cola y conservar/retirar/restaurar con
datos autorizados. El panel depende de esas rutas y se activa despues. Las pruebas
locales no sustituyen esa comprobacion operativa ni autorizan un despliegue.

## Circuito de Administracion SportCenter (rolAdmin / rol 3)

1. Consultar la cola privada de reportes pendientes y abrir el folio. Verificar
   reseña, producto, motivo e historial; una referencia invalida no habilita una
   decision sobre otra reseña.
2. Elegir conservar, retirar o restaurar e indicar un motivo concreto.
   Conservar mantiene la visibilidad actual, incluida una retirada anterior.
   Retirar oculta la reseña de la consulta publica y sus agregados; restaurar
   permite verla de nuevo. El actor se obtiene de la sesion activa del servidor.
3. Guardar una sola vez. Ante conflicto409 o resultado incierto, actualizar
   la revision y revisar el historial antes de decidir; no repetir el POST
   automaticamente.
4. Comprobar el nuevo estado, historial y consulta publica desde otra cuenta.
   El folio original se conserva y se marca leido. Esto no significa que se
   haya enviado una respuesta: `respondido` no cambia por moderar.

La demostracion automatizada con cuentas sinteticas acredita el circuito local.
La disponibilidad de la administracion y la atencion de reportes reales deben
comprobarse al activar el entorno autorizado; no se declara un horario o plazo
de atencion que no se haya acordado.

## Reversion y conservacion del historial

La migracion se niega a revertir si hay decisiones o reseñas retiradas. No se debe
borrar el historial ni cambiar su contenido para forzar una reversion.

Volver sin mas al backend anterior tambien es peligroso: sus consultas ignoran
`retirada` y volverian a mostrar contenido moderado. Cualquier reversion de codigo
debe conservar el filtro publico y la evidencia de las decisiones; ante un fallo,
se debe corregir esa version o suspender temporalmente la consulta afectada antes
que volver a publicar reseñas retiradas.
