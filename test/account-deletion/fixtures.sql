-- Synthetic PostgreSQL integration variant, never production DDL/data.
-- Historical QA baseline used public.contact_messages. The current moderation
-- migration requires it in core; move before applying that real migration.
ALTER TABLE public.contact_messages SET SCHEMA core;

-- Simulates inherited/default read privileges that the private migration must
-- actively remove, while preserving the explicitly authorized backup reader.
ALTER DEFAULT PRIVILEGES IN SCHEMA core GRANT SELECT ON TABLES TO qa_reader,qa_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO qa_reader,qa_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA core GRANT SELECT ON SEQUENCES TO qa_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO qa_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA core,public TO qa_backup;

-- Deliberately stronger synthetic FK graph than the historical QA dump (0FK).
ALTER TABLE core.user_sessions ADD CONSTRAINT qa_deletion_session_user FOREIGN KEY(id_usuario) REFERENCES core.users(id_usuario) ON DELETE RESTRICT;
ALTER TABLE core.direcciones ADD CONSTRAINT qa_deletion_address_user FOREIGN KEY(id_usuario) REFERENCES core.users(id_usuario) ON DELETE RESTRICT;
ALTER TABLE core.carts ADD CONSTRAINT qa_deletion_cart_user FOREIGN KEY(id_usuario) REFERENCES core.users(id_usuario) ON DELETE RESTRICT;
ALTER TABLE core.cart_items ADD CONSTRAINT qa_deletion_cart_item_cart FOREIGN KEY(id_carrito) REFERENCES core.carts(id_carrito) ON DELETE RESTRICT;
ALTER TABLE core.orders ADD CONSTRAINT qa_deletion_order_user FOREIGN KEY(id_usuario) REFERENCES core.users(id_usuario) ON DELETE RESTRICT;
ALTER TABLE core.orders ADD CONSTRAINT qa_deletion_order_address FOREIGN KEY(id_direccion_envio) REFERENCES core.direcciones(id_direccion) ON DELETE RESTRICT;
ALTER TABLE core.order_items ADD CONSTRAINT qa_deletion_order_item_order FOREIGN KEY(id_orden) REFERENCES core.orders(id_orden) ON DELETE RESTRICT;
ALTER TABLE core.pagos ADD CONSTRAINT qa_deletion_payment_order FOREIGN KEY(id_orden) REFERENCES core.orders(id_orden) ON DELETE RESTRICT;
ALTER TABLE core.shipments ADD CONSTRAINT qa_deletion_shipment_order FOREIGN KEY(id_orden) REFERENCES core.orders(id_orden) ON DELETE RESTRICT;
ALTER TABLE core.reviews ADD CONSTRAINT qa_deletion_review_user FOREIGN KEY(id_usuario) REFERENCES core.users(id_usuario) ON DELETE RESTRICT;
ALTER TABLE core.user_payment_methods ADD CONSTRAINT qa_deletion_payment_method_user FOREIGN KEY(id_usuario) REFERENCES core.users(id_usuario) ON DELETE RESTRICT;

CREATE TABLE core.returns (
  id_devolucion integer PRIMARY KEY,
  id_orden integer NOT NULL REFERENCES core.orders(id_orden) ON DELETE RESTRICT,
  id_usuario integer NOT NULL REFERENCES core.users(id_usuario) ON DELETE RESTRICT,
  estado varchar(40) NOT NULL,motivo text,descripcion text,resolucion text,
  solicitado_en timestamp NOT NULL DEFAULT clock_timestamp(),fecha_actualizacion timestamp,
  resuelto_por integer REFERENCES core.users(id_usuario) ON DELETE RESTRICT,resuelto_en timestamp
);
CREATE TABLE core.return_items (
  id_devolucion integer NOT NULL REFERENCES core.returns(id_devolucion) ON DELETE RESTRICT,
  id_orden integer NOT NULL REFERENCES core.orders(id_orden) ON DELETE RESTRICT,
  id_variante integer NOT NULL,cantidad integer NOT NULL,precio_unitario numeric(10,2) NOT NULL,
  total numeric(10,2) NOT NULL,motivo text,aprobado boolean,
  PRIMARY KEY(id_devolucion,id_variante)
);
CREATE TABLE core.return_events (
  id_devolucion integer NOT NULL REFERENCES core.returns(id_devolucion) ON DELETE RESTRICT,
  estado varchar(40) NOT NULL,comentario text,
  registrado_por integer REFERENCES core.users(id_usuario) ON DELETE RESTRICT,
  PRIMARY KEY(id_devolucion,estado)
);

INSERT INTO core.users(id_usuario,nombre,"aPaterno","aMaterno",email,telefono,passw,rol,activo,email_verified,telefono_verified,google_id,ubicacion)
SELECT n,'QA persona '||n,'Sintetica','Aislada','deletion-'||n||'@qa.invalid','5500000101','synthetic-non-secret-password-hash',1,1,1,1,'synthetic-google-'||n,NULL FROM generate_series(710101,710112) n;
INSERT INTO core.users(id_usuario,nombre,"aPaterno","aMaterno",email,passw,rol,activo,email_verified)
VALUES(710199,'QA admin','Sintetico','Aislado','deletion-admin@qa.invalid','synthetic-non-secret-password-hash',3,1,1);
INSERT INTO core.user_sessions(id_sesion,id_usuario,refresh_token_hash,device_name,user_agent,ip_address,expira_en)
SELECT ('71000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,n,'synthetic-refresh-hash','QA device','QA agent','127.0.0.1',clock_timestamp()+interval '1 hour' FROM generate_series(710101,710112) n;
-- A second session tests revocation beyond the requesting device.
INSERT INTO core.user_sessions(id_sesion,id_usuario,refresh_token_hash,expira_en)
VALUES('72000000-0000-4000-8000-000000710101',710101,'synthetic-second-refresh',clock_timestamp()+interval '1 hour');
INSERT INTO core.direcciones(id_direccion,id_usuario,alias,calle,numero,colonia,ciudad,estado,codigo_postal,pais,principal)
SELECT n,n,'Direccion QA','Calle sintetica','1','Pruebas','Ciudad QA','Estado QA','00000','QA',true FROM generate_series(710101,710112) n;
INSERT INTO core.carts(id_carrito,id_usuario,estado) SELECT n,n,'activo' FROM generate_series(710101,710112)n;
INSERT INTO core.cart_items(id_carrito,id_variante,cantidad,precio_unitario) SELECT n,1,1,100 FROM generate_series(710101,710112)n;
INSERT INTO core.user_payment_methods(id_metodo_pago,id_usuario,alias,marca,titular,ultimos4,exp_mes,exp_anio,principal,activo)
SELECT n,n,'QA metodo','QA','Titular QA','0000',1,2099,true,true FROM generate_series(710101,710112)n;
INSERT INTO core.reviews(id_review,id_producto,id_usuario,calificacion,comentario)
SELECT n,1,n,4,'Texto sintetico privado '||n FROM generate_series(710101,710112)n;
INSERT INTO core.contact_messages(id_mensaje,nombre,email,telefono,asunto,mensaje)
SELECT n,'Nombre sintetico '||n,'deletion-'||n||'@qa.invalid','5500000101','Solicitud QA','Contenido personal sintetico '||n FROM generate_series(710101,710112)n;
INSERT INTO core.orders(id_orden,id_usuario,id_direccion_envio,estado,subtotal,descuento,total,metodo_pago)
VALUES(710103,710103,710103,'pendiente',100,0,100,'qa'),(710104,710104,710104,'entregado',100,0,100,'qa');
INSERT INTO core.order_items(id_orden,id_variante,sku,nombre_producto,cantidad,precio_unitario,total)
VALUES(710103,1,'QA-SKU','QA producto',1,100,100),(710104,1,'QA-SKU','QA producto',1,100,100);
INSERT INTO core.pagos(id_pago,id_orden,proveedor_pago,referencia_externa,monto,estado)
VALUES(710104,710104,'qa-no-provider','synthetic-qa-reference',100,'approved');
INSERT INTO core.shipments(id_envio,id_orden,estado,numero_guia,paqueteria,costo_envio,codigo_confirmacion_entrega)
VALUES(710104,710104,'entregado','QA-private-guide','QA-private-carrier',0,'QA-delivery-code');
INSERT INTO core.returns(id_devolucion,id_orden,id_usuario,estado,motivo,descripcion,resolucion)
VALUES(710104,710104,710104,'completada','QA private return reason','QA private return description','QA private return resolution');
INSERT INTO core.return_items(id_devolucion,id_orden,id_variante,cantidad,precio_unitario,total,motivo,aprobado)
VALUES(710104,710104,1,1,100,100,'QA private return item reason',true);
INSERT INTO core.return_events(id_devolucion,estado,comentario,registrado_por)
VALUES(710104,'completada','QA private return event comment',710104);

-- A finished order can still need its delivery address for a pending return.
INSERT INTO core.users(id_usuario,nombre,"aPaterno","aMaterno",email,telefono,passw,rol,activo,email_verified)
VALUES(710113,'QA return','Synthetic','Local','deletion-710113@qa.invalid','5500000113','qa-only',1,1,1);
INSERT INTO core.user_sessions(id_sesion,id_usuario,refresh_token_hash,expira_en)
VALUES('71000000-0000-4000-8000-000000710113',710113,'qa-only',clock_timestamp()+interval '1 hour');
INSERT INTO core.direcciones(id_direccion,id_usuario,alias,calle,numero,colonia,ciudad,estado,codigo_postal,pais,principal)
VALUES(710113,710113,'QA return address','Calle sintetica devolucion','13','QA','Ciudad QA','Estado QA','00000','QA',true);
INSERT INTO core.orders(id_orden,id_usuario,id_direccion_envio,estado,subtotal,descuento,total,metodo_pago)
VALUES(710113,710113,710113,'entregado',100,0,100,'qa');
INSERT INTO core.returns(id_devolucion,id_orden,id_usuario,estado,motivo,descripcion)
VALUES(710113,710113,710113,'solicitada','QA pending return reason','QA pending return description');
