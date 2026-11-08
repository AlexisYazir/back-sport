-- DDL-only baseline extracted from a preserved SYNTHETIC QA scenario.
-- Not a production schema attestation; no COPY/INSERT/data/roles/grants/owners.
CREATE SCHEMA core;

CREATE TABLE core.attributes (
    id_atributo integer NOT NULL,
    nombre character varying(100) NOT NULL,
    id_padre integer NOT NULL
);

CREATE SEQUENCE core.attributes_id_atributo_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.attributes_id_atributo_seq OWNED BY core.attributes.id_atributo;

CREATE TABLE core.backup_retention_policies (
    id_retention_policy integer NOT NULL,
    nombre character varying(120) NOT NULL,
    tipo_backup character varying(20),
    carpeta_base character varying(150) DEFAULT 'backups'::character varying NOT NULL,
    retencion_dias integer DEFAULT 7 NOT NULL,
    modo_programacion character varying(20) NOT NULL,
    cron_expression character varying(100),
    dia_semana smallint,
    hora time without time zone,
    fecha_ejecucion timestamp without time zone,
    activo boolean DEFAULT true NOT NULL,
    ultima_ejecucion timestamp without time zone,
    proxima_ejecucion timestamp without time zone,
    creado_en timestamp without time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp without time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE core.backup_retention_policies_id_retention_policy_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.backup_retention_policies_id_retention_policy_seq OWNED BY core.backup_retention_policies.id_retention_policy;

CREATE TABLE core.backup_schedules (
    id_backup_schedule integer NOT NULL,
    nombre character varying(120) NOT NULL,
    tipo_backup character varying(20) NOT NULL,
    modo_programacion character varying(20) NOT NULL,
    cron_expression character varying(100),
    dia_semana smallint,
    hora time without time zone,
    fecha_ejecucion timestamp without time zone,
    activo boolean DEFAULT true NOT NULL,
    ultima_ejecucion timestamp without time zone,
    proxima_ejecucion timestamp without time zone,
    carpeta_destino character varying(150) DEFAULT 'backups'::character varying,
    retencion_dias integer DEFAULT 7 NOT NULL,
    creado_en timestamp without time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp without time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE core.backup_schedules_id_backup_schedule_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.backup_schedules_id_backup_schedule_seq OWNED BY core.backup_schedules.id_backup_schedule;

CREATE TABLE core.cart_items (
    id_carrito integer NOT NULL,
    id_variante integer NOT NULL,
    cantidad integer NOT NULL,
    precio_unitario numeric(10,2) NOT NULL
);

CREATE TABLE core.carts (
    id_carrito integer NOT NULL,
    id_usuario integer NOT NULL,
    estado character varying(100),
    fecha_creacion timestamp without time zone,
    fecha_actualizacion timestamp without time zone
);

CREATE TABLE core.categories (
    id_categoria integer NOT NULL,
    nombre character varying(100) NOT NULL,
    id_padre integer
);

CREATE SEQUENCE core.categories_id_categoria_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.categories_id_categoria_seq OWNED BY core.categories.id_categoria;

CREATE SEQUENCE core.checkout_qa_carts_id_seq
    AS integer
    START WITH 920001
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.checkout_qa_carts_id_seq OWNED BY core.carts.id_carrito;

CREATE TABLE core.direcciones (
    id_direccion integer NOT NULL,
    id_usuario integer NOT NULL,
    alias character varying(50),
    calle character varying(150),
    numero character varying(20),
    colonia character varying(100),
    ciudad character varying(100),
    estado character varying(100),
    codigo_postal character varying(10),
    pais character varying(100),
    principal boolean DEFAULT false NOT NULL,
    fecha_creacion timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

CREATE SEQUENCE core.checkout_qa_direcciones_id_seq
    AS integer
    START WITH 920001
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.checkout_qa_direcciones_id_seq OWNED BY core.direcciones.id_direccion;

CREATE TABLE core.pagos (
    id_pago integer NOT NULL,
    id_orden integer NOT NULL,
    proveedor_pago text NOT NULL,
    referencia_externa text NOT NULL,
    monto numeric(10,2) NOT NULL,
    estado character varying(100) NOT NULL,
    fecha_creacion timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE SEQUENCE core.checkout_qa_pagos_id_seq
    AS integer
    START WITH 920001
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.checkout_qa_pagos_id_seq OWNED BY core.pagos.id_pago;

CREATE TABLE core.shipment_events (
    id_evento integer NOT NULL,
    id_envio integer NOT NULL,
    estado character varying(100),
    titulo character varying(150),
    descripcion text,
    ubicacion character varying(150),
    fecha_evento timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    registrado_por integer
);

CREATE SEQUENCE core.checkout_qa_shipment_events_id_seq
    AS integer
    START WITH 920001
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.checkout_qa_shipment_events_id_seq OWNED BY core.shipment_events.id_evento;

CREATE TABLE core.shipments (
    id_envio integer NOT NULL,
    id_orden integer NOT NULL,
    id_metodo_envio integer,
    estado character varying(100),
    numero_guia character varying(100),
    paqueteria character varying(100),
    costo_envio numeric(10,2),
    fecha_entrega_estimada timestamp without time zone,
    fecha_entrega timestamp without time zone,
    codigo_confirmacion_entrega character varying(100),
    codigo_confirmacion_generado_en timestamp without time zone,
    entrega_confirmada_por_usuario boolean,
    entrega_confirmada_en timestamp without time zone,
    entrega_validada_por_empleado boolean,
    entrega_validada_en timestamp without time zone,
    creado_por integer,
    actualizado_por integer,
    fecha_creacion timestamp without time zone,
    fecha_actualizacion timestamp without time zone
);

CREATE SEQUENCE core.checkout_qa_shipments_id_seq
    AS integer
    START WITH 920001
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.checkout_qa_shipments_id_seq OWNED BY core.shipments.id_envio;

CREATE TABLE core.deportes (
    id_deporte integer NOT NULL,
    nombre character varying(100) NOT NULL
);

CREATE SEQUENCE core.deportes_id_deporte_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.deportes_id_deporte_seq OWNED BY core.deportes.id_deporte;

CREATE TABLE core.inventory (
    id_inventory integer NOT NULL,
    id_variante integer NOT NULL,
    stock_actual integer NOT NULL,
    costo_promedio numeric(10,2) DEFAULT '0'::numeric NOT NULL
);

CREATE SEQUENCE core.inventory_id_inventory_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.inventory_id_inventory_seq OWNED BY core.inventory.id_inventory;

CREATE TABLE core.inventory_movements (
    id_movimiento integer NOT NULL,
    id_variante integer NOT NULL,
    tipo character varying(100) NOT NULL,
    cantidad integer NOT NULL,
    costo_unitario numeric(10,2) DEFAULT '0'::numeric NOT NULL,
    referencia_tipo character varying(100) NOT NULL,
    referencia_id integer NOT NULL,
    fecha timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE core.inventory_movements_id_movimiento_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.inventory_movements_id_movimiento_seq OWNED BY core.inventory_movements.id_movimiento;

CREATE TABLE core.marcas (
    id_marca integer NOT NULL,
    nombre character varying(100) NOT NULL,
    imagen text NOT NULL
);

CREATE SEQUENCE core.marcas_id_marca_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.marcas_id_marca_seq OWNED BY core.marcas.id_marca;

CREATE TABLE core.order_discounts (
    id_orden integer NOT NULL,
    id_promocion integer,
    codigo text,
    descripcion text,
    monto numeric(10,2) NOT NULL
);

CREATE TABLE core.order_items (
    id_orden integer NOT NULL,
    id_variante integer NOT NULL,
    sku character varying(100),
    nombre_producto character varying(255),
    cantidad integer NOT NULL,
    precio_unitario numeric(10,2) NOT NULL,
    total numeric(10,2) NOT NULL
);

CREATE TABLE core.order_status_history (
    id_orden integer NOT NULL,
    estado_anterior character varying(100),
    estado_nuevo character varying(100) NOT NULL,
    comentario text,
    cambiado_por integer
);

CREATE TABLE core.orders (
    id_orden integer NOT NULL,
    id_usuario integer NOT NULL,
    id_direccion_envio integer NOT NULL,
    estado character varying(100) NOT NULL,
    subtotal numeric(10,2) DEFAULT '0'::numeric NOT NULL,
    descuento numeric(10,2) DEFAULT '0'::numeric NOT NULL,
    total numeric(10,2) DEFAULT '0'::numeric NOT NULL,
    metodo_pago text NOT NULL,
    fecha_pago timestamp without time zone,
    fecha_envio timestamp without time zone,
    fecha_entrega timestamp without time zone,
    fecha_creacion timestamp without time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE core.orders_id_orden_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.orders_id_orden_seq OWNED BY core.orders.id_orden;

CREATE TABLE core.product_deportes (
    id_producto integer NOT NULL,
    id_deporte integer NOT NULL
);

CREATE TABLE core.product_variants (
    id_variante integer NOT NULL,
    id_producto integer NOT NULL,
    sku character varying(100) NOT NULL,
    precio numeric(10,2) DEFAULT '0'::numeric NOT NULL,
    imagenes jsonb DEFAULT '[]'::jsonb NOT NULL,
    atributos jsonb DEFAULT '{}'::jsonb NOT NULL
);

CREATE SEQUENCE core.product_variants_id_variante_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.product_variants_id_variante_seq OWNED BY core.product_variants.id_variante;

CREATE TABLE core.products (
    id_producto integer NOT NULL,
    nombre character varying(100) NOT NULL,
    descripcion text NOT NULL,
    id_categoria integer NOT NULL,
    id_marca integer NOT NULL,
    activo boolean DEFAULT false NOT NULL,
    fecha_creacion timestamp without time zone DEFAULT now() NOT NULL,
    fecha_actualizacion timestamp without time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE core.products_id_producto_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.products_id_producto_seq OWNED BY core.products.id_producto;

CREATE TABLE core.reviews (
    id_review integer NOT NULL,
    id_producto integer NOT NULL,
    id_usuario integer NOT NULL,
    calificacion integer NOT NULL,
    comentario text NOT NULL,
    fecha timestamp without time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE core.reviews_id_review_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.reviews_id_review_seq OWNED BY core.reviews.id_review;

CREATE TABLE core.roles (
    id_rol integer NOT NULL,
    rol character varying(100) NOT NULL
);

CREATE SEQUENCE core.roles_id_rol_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.roles_id_rol_seq OWNED BY core.roles.id_rol;

CREATE TABLE core.shipping_methods (
    id_metodo_envio integer NOT NULL,
    nombre character varying(100),
    descripcion text,
    costo_base numeric(10,2),
    envio_gratis_desde numeric(10,2),
    dias_min integer,
    dias_max integer,
    activo boolean
);

CREATE TABLE core.user_payment_methods (
    id_metodo_pago integer NOT NULL,
    id_usuario integer,
    alias character varying(100),
    marca character varying(100),
    titular character varying(100),
    ultimos4 character varying(4),
    exp_mes integer,
    exp_anio integer,
    principal boolean,
    activo boolean,
    fecha_creacion timestamp without time zone,
    fecha_actualizacion timestamp without time zone
);

CREATE TABLE core.user_sessions (
    id_sesion uuid NOT NULL,
    id_usuario integer NOT NULL,
    refresh_token_hash character varying(255) NOT NULL,
    device_name character varying(150),
    user_agent text,
    ip_address inet,
    creada_en timestamp without time zone DEFAULT now() NOT NULL,
    ultima_actividad timestamp without time zone DEFAULT now() NOT NULL,
    expira_en timestamp without time zone NOT NULL,
    revocada_en timestamp without time zone,
    motivo_revocacion character varying(100),
    reemplazada_por uuid,
    csrf_token_hash character varying(255)
);

CREATE TABLE core.users (
    id_usuario integer NOT NULL,
    nombre character varying(30) NOT NULL,
    "aPaterno" character varying(40) NOT NULL,
    "aMaterno" character varying(40) NOT NULL,
    email character varying(100),
    telefono character varying(15),
    passw character varying(255) NOT NULL,
    rol integer,
    activo integer,
    token_verificacion character varying(255),
    token_expiracion timestamp without time zone,
    intentos_token integer,
    fecha_creacion timestamp without time zone DEFAULT now() NOT NULL,
    fecha_actualizacion timestamp without time zone DEFAULT now() NOT NULL,
    email_verified integer,
    telefono_verified integer,
    google_id character varying(255),
    ubicacion integer
);

CREATE SEQUENCE core.users_id_usuario_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.users_id_usuario_seq OWNED BY core.users.id_usuario;

CREATE TABLE core.vacuum_schedules (
    id_vacuum_schedule integer NOT NULL,
    nombre character varying(120) NOT NULL,
    modo_programacion character varying(20) NOT NULL,
    cron_expression character varying(100),
    dia_semana smallint,
    hora time without time zone,
    fecha_ejecucion timestamp without time zone,
    esquema_objetivo character varying(100) DEFAULT 'core'::character varying NOT NULL,
    activo boolean DEFAULT true NOT NULL,
    ultima_ejecucion timestamp without time zone,
    proxima_ejecucion timestamp without time zone,
    creado_en timestamp without time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp without time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE core.vacuum_schedules_id_vacuum_schedule_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE core.vacuum_schedules_id_vacuum_schedule_seq OWNED BY core.vacuum_schedules.id_vacuum_schedule;

CREATE TABLE core.variant_attribute_values (
    id_variante integer NOT NULL,
    id_atributo integer NOT NULL,
    valor character varying(100) NOT NULL
);

CREATE TABLE public.company_info (
    id_empresa integer NOT NULL,
    nombre character varying(100) NOT NULL,
    rfc character varying(13),
    telefono character varying(15),
    email character varying(100),
    sitio_web character varying(255),
    id_direccion integer,
    facebook character varying(255),
    instagram character varying(255),
    twitter character varying(255),
    tiktok character varying(255),
    youtube character varying(255),
    regimen_fiscal character varying(100),
    logo_url character varying(500),
    horario_atencion text,
    mision text,
    vision text,
    valores text[] DEFAULT '{}'::text[] NOT NULL,
    mapa_ubicacion text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.company_info_id_empresa_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.company_info_id_empresa_seq OWNED BY public.company_info.id_empresa;

CREATE TABLE public.contact_messages (
    id_mensaje integer NOT NULL,
    nombre character varying(100) NOT NULL,
    email character varying(100) NOT NULL,
    telefono character varying(15),
    asunto character varying(200),
    mensaje text NOT NULL,
    leido boolean DEFAULT false NOT NULL,
    respondido boolean DEFAULT false NOT NULL,
    fecha_lectura timestamp without time zone,
    id_usuario_responde integer,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.contact_messages_id_mensaje_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.contact_messages_id_mensaje_seq OWNED BY public.contact_messages.id_mensaje;

CREATE TABLE public.faqs (
    id_faq integer NOT NULL,
    pregunta text NOT NULL,
    respuesta text NOT NULL,
    orden integer DEFAULT 0 NOT NULL,
    seccion character varying(50),
    palabras_clave text[] DEFAULT '{}'::text[] NOT NULL,
    activo boolean DEFAULT true NOT NULL,
    destacado boolean DEFAULT false NOT NULL,
    contador_vistas integer DEFAULT 0 NOT NULL,
    contador_util integer DEFAULT 0 NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.faqs_id_faq_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.faqs_id_faq_seq OWNED BY public.faqs.id_faq;

ALTER TABLE ONLY core.attributes ALTER COLUMN id_atributo SET DEFAULT nextval('core.attributes_id_atributo_seq'::regclass);

ALTER TABLE ONLY core.backup_retention_policies ALTER COLUMN id_retention_policy SET DEFAULT nextval('core.backup_retention_policies_id_retention_policy_seq'::regclass);

ALTER TABLE ONLY core.backup_schedules ALTER COLUMN id_backup_schedule SET DEFAULT nextval('core.backup_schedules_id_backup_schedule_seq'::regclass);

ALTER TABLE ONLY core.carts ALTER COLUMN id_carrito SET DEFAULT nextval('core.checkout_qa_carts_id_seq'::regclass);

ALTER TABLE ONLY core.categories ALTER COLUMN id_categoria SET DEFAULT nextval('core.categories_id_categoria_seq'::regclass);

ALTER TABLE ONLY core.deportes ALTER COLUMN id_deporte SET DEFAULT nextval('core.deportes_id_deporte_seq'::regclass);

ALTER TABLE ONLY core.direcciones ALTER COLUMN id_direccion SET DEFAULT nextval('core.checkout_qa_direcciones_id_seq'::regclass);

ALTER TABLE ONLY core.inventory ALTER COLUMN id_inventory SET DEFAULT nextval('core.inventory_id_inventory_seq'::regclass);

ALTER TABLE ONLY core.inventory_movements ALTER COLUMN id_movimiento SET DEFAULT nextval('core.inventory_movements_id_movimiento_seq'::regclass);

ALTER TABLE ONLY core.marcas ALTER COLUMN id_marca SET DEFAULT nextval('core.marcas_id_marca_seq'::regclass);

ALTER TABLE ONLY core.orders ALTER COLUMN id_orden SET DEFAULT nextval('core.orders_id_orden_seq'::regclass);

ALTER TABLE ONLY core.pagos ALTER COLUMN id_pago SET DEFAULT nextval('core.checkout_qa_pagos_id_seq'::regclass);

ALTER TABLE ONLY core.product_variants ALTER COLUMN id_variante SET DEFAULT nextval('core.product_variants_id_variante_seq'::regclass);

ALTER TABLE ONLY core.products ALTER COLUMN id_producto SET DEFAULT nextval('core.products_id_producto_seq'::regclass);

ALTER TABLE ONLY core.reviews ALTER COLUMN id_review SET DEFAULT nextval('core.reviews_id_review_seq'::regclass);

ALTER TABLE ONLY core.roles ALTER COLUMN id_rol SET DEFAULT nextval('core.roles_id_rol_seq'::regclass);

ALTER TABLE ONLY core.shipment_events ALTER COLUMN id_evento SET DEFAULT nextval('core.checkout_qa_shipment_events_id_seq'::regclass);

ALTER TABLE ONLY core.shipments ALTER COLUMN id_envio SET DEFAULT nextval('core.checkout_qa_shipments_id_seq'::regclass);

ALTER TABLE ONLY core.users ALTER COLUMN id_usuario SET DEFAULT nextval('core.users_id_usuario_seq'::regclass);

ALTER TABLE ONLY core.vacuum_schedules ALTER COLUMN id_vacuum_schedule SET DEFAULT nextval('core.vacuum_schedules_id_vacuum_schedule_seq'::regclass);

ALTER TABLE ONLY public.company_info ALTER COLUMN id_empresa SET DEFAULT nextval('public.company_info_id_empresa_seq'::regclass);

ALTER TABLE ONLY public.contact_messages ALTER COLUMN id_mensaje SET DEFAULT nextval('public.contact_messages_id_mensaje_seq'::regclass);

ALTER TABLE ONLY public.faqs ALTER COLUMN id_faq SET DEFAULT nextval('public.faqs_id_faq_seq'::regclass);

ALTER TABLE ONLY core.product_variants
    ADD CONSTRAINT "PK_01b47e5b72c61a909e040bdb560" PRIMARY KEY (id_variante);

ALTER TABLE ONLY core.reviews
    ADD CONSTRAINT "PK_19d8f22a89434009e8d2c3098e7" PRIMARY KEY (id_review);

ALTER TABLE ONLY core.deportes
    ADD CONSTRAINT "PK_1ea3e1dd1fb46fff1e8ae1046d4" PRIMARY KEY (id_deporte);

ALTER TABLE ONLY core.roles
    ADD CONSTRAINT "PK_25f8d4161f00a1dd1cbe5068695" PRIMARY KEY (id_rol);

ALTER TABLE ONLY core.inventory
    ADD CONSTRAINT "PK_2cdc32684ad0baa9e8d3971b8fe" PRIMARY KEY (id_inventory);

ALTER TABLE ONLY core.vacuum_schedules
    ADD CONSTRAINT "PK_4d739e4765c5bc66fba1b4d7f8b" PRIMARY KEY (id_vacuum_schedule);

ALTER TABLE ONLY core.user_sessions
    ADD CONSTRAINT "PK_4fc51a90452c2013c312bb52a23" PRIMARY KEY (id_sesion);

ALTER TABLE ONLY core.marcas
    ADD CONSTRAINT "PK_5fc3058a1b5da0007232e4ee5e0" PRIMARY KEY (id_marca);

ALTER TABLE ONLY core.orders
    ADD CONSTRAINT "PK_7363df31da5fb1770951b50c3a4" PRIMARY KEY (id_orden);

ALTER TABLE ONLY core.products
    ADD CONSTRAINT "PK_7b315fa7aeb5738af67bc444e83" PRIMARY KEY (id_producto);

ALTER TABLE ONLY core.categories
    ADD CONSTRAINT "PK_9138ae2fc8789b34c93311ddb47" PRIMARY KEY (id_categoria);

ALTER TABLE ONLY core.users
    ADD CONSTRAINT "PK_b2826bc9a58e9aba252457ad50b" PRIMARY KEY (id_usuario);

ALTER TABLE ONLY core.variant_attribute_values
    ADD CONSTRAINT "PK_b4e403648efc9245b58dab82133" PRIMARY KEY (id_variante, id_atributo);

ALTER TABLE ONLY core.inventory_movements
    ADD CONSTRAINT "PK_ba806bafaa617a6bdb0d2d7b8e5" PRIMARY KEY (id_movimiento);

ALTER TABLE ONLY core.attributes
    ADD CONSTRAINT "PK_bd2b7b4aee970687070c787f4fc" PRIMARY KEY (id_atributo);

ALTER TABLE ONLY core.backup_schedules
    ADD CONSTRAINT "PK_d8854df0278e8e58eeeae0b74ff" PRIMARY KEY (id_backup_schedule);

ALTER TABLE ONLY core.backup_retention_policies
    ADD CONSTRAINT "PK_e159190c48c47a718f7b24a6baa" PRIMARY KEY (id_retention_policy);

ALTER TABLE ONLY core.product_deportes
    ADD CONSTRAINT "PK_ff522d2ce395b1c3637e9bafedb" PRIMARY KEY (id_producto, id_deporte);

ALTER TABLE ONLY core.backup_schedules
    ADD CONSTRAINT "UQ_3ffcada2e8f68241463e9db4a77" UNIQUE (nombre);

ALTER TABLE ONLY core.backup_retention_policies
    ADD CONSTRAINT "UQ_8c8538bd086d1aa220339061625" UNIQUE (nombre);

ALTER TABLE ONLY core.vacuum_schedules
    ADD CONSTRAINT "UQ_fac4ba534764b557541593ea8f4" UNIQUE (nombre);

ALTER TABLE ONLY core.cart_items
    ADD CONSTRAINT cart_items_pkey PRIMARY KEY (id_carrito, id_variante);

ALTER TABLE ONLY core.carts
    ADD CONSTRAINT carts_pkey PRIMARY KEY (id_carrito);

ALTER TABLE ONLY core.direcciones
    ADD CONSTRAINT direcciones_pkey PRIMARY KEY (id_direccion);

ALTER TABLE ONLY core.order_items
    ADD CONSTRAINT order_items_pkey PRIMARY KEY (id_orden, id_variante);

ALTER TABLE ONLY core.pagos
    ADD CONSTRAINT pagos_pkey PRIMARY KEY (id_pago);

ALTER TABLE ONLY core.shipment_events
    ADD CONSTRAINT shipment_events_pkey PRIMARY KEY (id_evento);

ALTER TABLE ONLY core.shipments
    ADD CONSTRAINT shipments_id_orden_key UNIQUE (id_orden);

ALTER TABLE ONLY core.shipments
    ADD CONSTRAINT shipments_pkey PRIMARY KEY (id_envio);

ALTER TABLE ONLY core.shipping_methods
    ADD CONSTRAINT shipping_methods_pkey PRIMARY KEY (id_metodo_envio);

ALTER TABLE ONLY core.user_payment_methods
    ADD CONSTRAINT user_payment_methods_pkey PRIMARY KEY (id_metodo_pago);

ALTER TABLE ONLY public.faqs
    ADD CONSTRAINT "PK_0f7a2b1c5a8b88a2bccd790a766" PRIMARY KEY (id_faq);

ALTER TABLE ONLY public.company_info
    ADD CONSTRAINT "PK_2f0f4b5247f23a1e3b9ce872744" PRIMARY KEY (id_empresa);

ALTER TABLE ONLY public.contact_messages
    ADD CONSTRAINT "PK_eca8c0f83a4b15e65e2b8c6f2cb" PRIMARY KEY (id_mensaje);

CREATE UNIQUE INDEX "IDX_398299d68e78b1505b5bda3792" ON core.reviews USING btree (id_producto, id_usuario);

CREATE UNIQUE INDEX "IDX_46f236f21640f9da218a063a86" ON core.product_variants USING btree (sku);
