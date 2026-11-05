-- Esquema minimo de las entidades previas a moderacion, solo PostgreSQL efimero.
-- No es una copia productiva. La migracion real agrega sus columnas y controles.
DO $$ BEGIN
  IF current_database() <> 'sportcenter_moderation_qa' OR current_user <> 'qa_admin' THEN
    RAISE EXCEPTION 'MODERATION_QA_DATABASE_REQUIRED';
  END IF;
END $$;
CREATE SCHEMA core;
CREATE ROLE qa_editor LOGIN PASSWORD 'qa-editor-local';
CREATE ROLE qa_reader LOGIN PASSWORD 'qa-reader-local';
CREATE ROLE qa_backup LOGIN PASSWORD 'qa-backup-local';
GRANT USAGE ON SCHEMA core, public TO qa_editor, qa_reader, qa_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA core GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO qa_editor;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO qa_editor;
ALTER DEFAULT PRIVILEGES IN SCHEMA core GRANT SELECT ON TABLES TO qa_reader,qa_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO qa_reader,qa_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA core GRANT USAGE,SELECT ON SEQUENCES TO qa_editor;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO qa_editor;
CREATE TABLE core.users (
  id_usuario serial PRIMARY KEY,nombre varchar(30) NOT NULL,"aPaterno" varchar(40) NOT NULL,
  "aMaterno" varchar(40) NOT NULL,email varchar(100),telefono varchar(15),passw varchar(255) NOT NULL,
  rol integer,activo integer,token_verificacion varchar(255),token_expiracion timestamp,intentos_token integer,
  fecha_creacion timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,fecha_actualizacion timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  email_verified integer,telefono_verified integer,google_id varchar(255),ubicacion integer
);
CREATE TABLE core.user_sessions (
  id_sesion uuid PRIMARY KEY,id_usuario integer NOT NULL,refresh_token_hash varchar(255) NOT NULL,
  device_name varchar(150),user_agent text,ip_address inet,creada_en timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ultima_actividad timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,expira_en timestamp NOT NULL,revocada_en timestamp,
  motivo_revocacion varchar(100),reemplazada_por uuid,csrf_token_hash varchar(255)
);
CREATE TABLE core.products (
  id_producto serial PRIMARY KEY,nombre varchar(100) NOT NULL,descripcion text NOT NULL,
  id_categoria integer NOT NULL,id_marca integer NOT NULL,activo boolean NOT NULL DEFAULT false,
  fecha_creacion timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,fecha_actualizacion timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE core.reviews (
  id_review serial PRIMARY KEY,id_producto integer NOT NULL,id_usuario integer NOT NULL,
  calificacion integer NOT NULL,comentario text NOT NULL,fecha timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(id_producto,id_usuario)
);
CREATE TABLE public.contact_messages (
  id_mensaje serial PRIMARY KEY,nombre varchar(100) NOT NULL,email varchar(100) NOT NULL,
  telefono varchar(15),asunto varchar(200),mensaje text NOT NULL,leido boolean NOT NULL DEFAULT false,
  respondido boolean NOT NULL DEFAULT false,fecha_lectura timestamp,id_usuario_responde integer,
  created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE core.orders(id_orden integer PRIMARY KEY,id_usuario integer NOT NULL,estado text NOT NULL);
CREATE TABLE core.product_variants(id_variante integer PRIMARY KEY,id_producto integer NOT NULL);
CREATE TABLE core.order_items(id_orden integer NOT NULL,id_variante integer NOT NULL);
INSERT INTO core.users(id_usuario,nombre,"aPaterno","aMaterno",email,passw,rol,activo,email_verified)
SELECT 310000+n,'QA usuario '||n,'Sintetico','Local','moderation-'||n||'@qa.invalid','not-a-real-password',
  CASE WHEN n IN (3,4,5) THEN 3 ELSE n END,CASE WHEN n=4 THEN 0 ELSE 1 END,1 FROM generate_series(1,5) n;
INSERT INTO core.user_sessions(id_sesion,id_usuario,refresh_token_hash,expira_en)
SELECT ('10000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,310000+n,'not-a-real-refresh',
  CURRENT_TIMESTAMP+INTERVAL '1 hour' FROM generate_series(1,5) n;
INSERT INTO core.products(id_producto,nombre,descripcion,id_categoria,id_marca,activo)
VALUES(320001,'Producto QA Uno','Sintetico',1,1,true),(320002,'Producto QA Dos','Sintetico',1,1,true);
INSERT INTO core.reviews(id_review,id_producto,id_usuario,calificacion,comentario)
VALUES(330001,320001,310001,5,'Resena sintetica QA uno'),(330002,320001,310002,1,'Resena sintetica QA dos'),
      (330003,320002,310001,4,'Resena sintetica QA tres'),(330004,320002,310002,2,'Resena sintetica concurrente'),
      (330005,320002,310003,3,'Resena sintetica rollback');
INSERT INTO core.orders VALUES(340001,310001,'entregado');
INSERT INTO core.product_variants VALUES(350001,320001);
INSERT INTO core.order_items VALUES(340001,350001);
