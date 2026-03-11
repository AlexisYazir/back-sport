--
-- PostgreSQL database dump
--

\restrict ecpACbvzzocHOrxo3zW0QGHja0FUZ1YawvCNVK0v8fy0TDNEXbtW6kxhE9Zi9Sa

-- Dumped from database version 17.8 (6108b59)
-- Dumped by pg_dump version 18.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: core; Type: SCHEMA; Schema: -; Owner: neondb_owner
--

CREATE SCHEMA core;


ALTER SCHEMA core OWNER TO neondb_owner;

--
-- Name: reports; Type: SCHEMA; Schema: -; Owner: neondb_owner
--

CREATE SCHEMA reports;


ALTER SCHEMA reports OWNER TO neondb_owner;

--
-- Name: staging; Type: SCHEMA; Schema: -; Owner: neondb_owner
--

CREATE SCHEMA staging;


ALTER SCHEMA staging OWNER TO neondb_owner;

--
-- Name: create_inventory_after_variant(); Type: FUNCTION; Schema: core; Owner: neondb_owner
--

CREATE FUNCTION core.create_inventory_after_variant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO core.inventory (
        id_variante,
        stock_actual,
        costo_promedio
    )
    VALUES (
        NEW.id_variante,
        0,
        0
    );

    RETURN NEW;
END;
$$;


ALTER FUNCTION core.create_inventory_after_variant() OWNER TO neondb_owner;

--
-- Name: create_inventory_movement(integer, text, integer, numeric, text, integer); Type: FUNCTION; Schema: core; Owner: neondb_owner
--

CREATE FUNCTION core.create_inventory_movement(p_id_variante integer, p_tipo text, p_cantidad integer, p_costo_unitario numeric, p_referencia_tipo text, p_referencia_id integer) RETURNS TABLE(new_stock integer, new_costo_promedio numeric)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_stock_actual INT;
    v_costo_promedio NUMERIC(10,2);
    v_new_stock INT;
    v_new_costo NUMERIC(10,2);
BEGIN

    -- Obtener inventario actual
    SELECT stock_actual, costo_promedio
    INTO v_stock_actual, v_costo_promedio
    FROM core.inventory
    WHERE id_variante = p_id_variante;

    -- Si no existe inventario se crea
    IF NOT FOUND THEN
        INSERT INTO core.inventory(id_variante, stock_actual, costo_promedio)
        VALUES(p_id_variante, 0, 0);

        v_stock_actual := 0;
        v_costo_promedio := 0;
    END IF;

    -- Calcular nuevo stock
    IF p_tipo = 'entrada' THEN
        v_new_stock := v_stock_actual + p_cantidad;

        -- nuevo costo promedio ponderado
        v_new_costo := (
            (v_stock_actual * v_costo_promedio) +
            (p_cantidad * p_costo_unitario)
        ) / v_new_stock;

    ELSIF p_tipo = 'salida' THEN
        v_new_stock := v_stock_actual - p_cantidad;

        IF v_new_stock < 0 THEN
            RAISE EXCEPTION 'Stock insuficiente para la variante %', p_id_variante;
        END IF;

        v_new_costo := v_costo_promedio;

    ELSIF p_tipo = 'ajuste' THEN
        v_new_stock := p_cantidad;
        v_new_costo := p_costo_unitario;

    ELSE
        RAISE EXCEPTION 'Tipo de movimiento inválido';
    END IF;

    -- Registrar movimiento
    INSERT INTO core.inventory_movements(
        id_variante,
        tipo,
        cantidad,
        costo_unitario,
        referencia_tipo,
        referencia_id
    )
    VALUES(
        p_id_variante,
        p_tipo,
        p_cantidad,
        p_costo_unitario,
        p_referencia_tipo,
        p_referencia_id
    );

    -- Actualizar inventario
    UPDATE core.inventory
    SET stock_actual = v_new_stock,
        costo_promedio = v_new_costo
    WHERE id_variante = p_id_variante;

    RETURN QUERY
    SELECT v_new_stock, v_new_costo;

END;
$$;


ALTER FUNCTION core.create_inventory_movement(p_id_variante integer, p_tipo text, p_cantidad integer, p_costo_unitario numeric, p_referencia_tipo text, p_referencia_id integer) OWNER TO neondb_owner;

--
-- Name: get_all_products(); Type: FUNCTION; Schema: core; Owner: neondb_owner
--

CREATE FUNCTION core.get_all_products() RETURNS TABLE(id_producto integer, producto character varying, descripcion text, activo boolean, fecha_creacion timestamp without time zone, marca character varying, imagen_marca character varying, categoria character varying, categoria_padre character varying, variantes jsonb)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        p.id_producto,
        p.nombre AS producto,
        p.descripcion,
        p.activo,
        p.fecha_creacion,
        m.nombre AS marca,
        m.imagen,
        c.nombre AS categoria,
        cp.nombre AS categoria_padre,
        COALESCE(
            jsonb_agg(
                DISTINCT jsonb_build_object(
                    'id_variante', v.id_variante,
                    'sku', v.sku,
                    'precio', v.precio,
                    'stock', vi.stock_actual,
                    'imagenes', v.imagenes,
                    'atributos', v.atributos
                )
            ) FILTER (WHERE v.id_variante IS NOT NULL),
            '[]'::jsonb
        )
    FROM core.products p
    LEFT JOIN core.marcas m 
        ON m.id_marca = p.id_marca
    LEFT JOIN core.categories c 
        ON c.id_categoria = p.id_categoria
    LEFT JOIN core.categories cp 
        ON cp.id_categoria = c.id_padre
    LEFT JOIN core.product_variants v 
        ON v.id_producto = p.id_producto
	INNER JOIN core.inventory vi 
        ON vi.id_variante = v.id_variante
    GROUP BY 
        p.id_producto,
        p.nombre,
        p.descripcion,
        p.activo,
        p.fecha_creacion,
        m.nombre,
        m.imagen,
        c.nombre,
        cp.nombre;
END;
$$;


ALTER FUNCTION core.get_all_products() OWNER TO neondb_owner;

--
-- Name: get_inventory_products(); Type: FUNCTION; Schema: core; Owner: neondb_owner
--

CREATE FUNCTION core.get_inventory_products() RETURNS TABLE(id_producto integer, producto text, activo boolean, precio numeric, stock numeric, marca text, imagen text, fecha_creacion timestamp without time zone)
    LANGUAGE sql
    AS $$
    SELECT 
        t.id_producto,
        t.producto,
        t.activo,
        t.precio,
        t.stock_actual,
        t.marca,
        t.imagen,
        t.fecha_creacion
    FROM (
        SELECT DISTINCT ON (p.id_producto)
            p.id_producto,
            p.nombre AS producto,
            p.activo,
            v.precio,
            vi.stock_actual,
            m.nombre AS marca,
            m.imagen,
            p.fecha_creacion,
            CASE
                WHEN p.activo = false THEN 1
                WHEN vi.stock_actual < 5 THEN 2
                ELSE 3
            END AS prioridad
        FROM core.products p
        LEFT JOIN core.marcas m 
            ON m.id_marca = p.id_marca
        LEFT JOIN core.product_variants v 
            ON v.id_producto = p.id_producto
		INNER JOIN core.inventory vi
			ON vi.id_variante = v.id_variante
        ORDER BY p.id_producto, vi.stock_actual ASC
    ) t
    ORDER BY t.prioridad, t.stock_actual ASC;
$$;


ALTER FUNCTION core.get_inventory_products() OWNER TO neondb_owner;

--
-- Name: get_products_with_variants_without_attributes(); Type: FUNCTION; Schema: core; Owner: neondb_owner
--

CREATE FUNCTION core.get_products_with_variants_without_attributes() RETURNS TABLE(id_producto integer, nombre text, descripcion text, activo boolean, fecha_creacion timestamp without time zone)
    LANGUAGE sql
    AS $$
    SELECT 
        p.id_producto,
        p.nombre,
        p.descripcion,
        p.activo,
        p.fecha_creacion
    FROM core.products p
    WHERE EXISTS (
        SELECT 1
        FROM core.product_variants v
        WHERE v.id_producto = p.id_producto
    )
    AND EXISTS (
        SELECT 1
        FROM core.product_variants v
        WHERE v.id_producto = p.id_producto
          AND NOT EXISTS (
              SELECT 1
              FROM core.variant_attribute_values vav
              WHERE vav.id_variante = v.id_variante
          )
    )
    ORDER BY id_producto;
$$;


ALTER FUNCTION core.get_products_with_variants_without_attributes() OWNER TO neondb_owner;

--
-- Name: get_recients_products(); Type: FUNCTION; Schema: core; Owner: neondb_owner
--

CREATE FUNCTION core.get_recients_products() RETURNS TABLE(id_producto numeric, nombre text, descripcion text, activo boolean, fecha_creacion text)
    LANGUAGE sql
    AS $$
    SELECT 
        p.id_producto,
        p.nombre,
        p.descripcion,
        p.activo,
        p.fecha_creacion
    FROM core.products p
    WHERE NOT EXISTS (
        SELECT 1
        FROM core.product_variants v
        WHERE v.id_producto = p.id_producto
    )
	ORDER BY p.fecha_creacion DESC;
$$;


ALTER FUNCTION core.get_recients_products() OWNER TO neondb_owner;

--
-- Name: get_recients_users(); Type: FUNCTION; Schema: core; Owner: neondb_owner
--

CREATE FUNCTION core.get_recients_users() RETURNS TABLE(id numeric, nombre text, email text, rol numeric, activo numeric, fecha_creacion text)
    LANGUAGE sql
    AS $$
    SELECT id_usuario, nombre, email, rol, activo, fecha_creacion
    FROM core.users
    ORDER BY fecha_creacion ASC
    LIMIT 10;
$$;


ALTER FUNCTION core.get_recients_users() OWNER TO neondb_owner;

--
-- Name: get_variants_product_by_id(integer); Type: FUNCTION; Schema: core; Owner: neondb_owner
--

CREATE FUNCTION core.get_variants_product_by_id(id_producto_p integer) RETURNS TABLE(id_variante integer, id_producto integer, sku text, precio numeric, stock integer, imagenes jsonb, atributos jsonb)
    LANGUAGE sql
    AS $$
    SELECT 
        pv.id_variante,
        pv.id_producto,
        pv.sku,
        pv.precio,
        pvi.stock_actual AS stock,
        pv.imagenes,
		pv.atributos
    FROM core.product_variants pv
    INNER JOIN core.inventory pvi
        ON pvi.id_variante = pv.id_variante
    WHERE pv.id_producto = id_producto_p;
$$;


ALTER FUNCTION core.get_variants_product_by_id(id_producto_p integer) OWNER TO neondb_owner;

--
-- Name: update_full_product(integer, integer, integer, text, text); Type: FUNCTION; Schema: core; Owner: neondb_owner
--

CREATE FUNCTION core.update_full_product(p_id_producto integer, p_id_marca integer, p_id_categoria integer, p_nombre text, p_descripcion text) RETURNS TABLE(updated_product integer)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_rows_product INT := 0;
BEGIN
    UPDATE core.products
    SET id_marca = p_id_marca,
        id_categoria = p_id_categoria,
        nombre = p_nombre,
        descripcion = p_descripcion,
        fecha_actualizacion = NOW()
    WHERE id_producto = p_id_producto;

    GET DIAGNOSTICS v_rows_product = ROW_COUNT;

    RETURN QUERY SELECT v_rows_product;
END;
$$;


ALTER FUNCTION core.update_full_product(p_id_producto integer, p_id_marca integer, p_id_categoria integer, p_nombre text, p_descripcion text) OWNER TO neondb_owner;

--
-- Name: update_product_variant(integer, integer, text, jsonb, numeric, jsonb); Type: FUNCTION; Schema: core; Owner: neondb_owner
--

CREATE FUNCTION core.update_product_variant(p_id_producto integer, p_id_variante integer, p_sku text, p_imagenes jsonb, p_precio numeric, p_atributos jsonb) RETURNS TABLE(updated_variant integer)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_rows_variant INT := 0;
BEGIN
    UPDATE core.product_variants
    SET sku = p_sku,
        imagenes = p_imagenes,
        precio = p_precio,
		atributos = p_atributos
    WHERE id_variante = p_id_variante
      AND id_producto = p_id_producto;

    GET DIAGNOSTICS v_rows_variant = ROW_COUNT;

    RETURN QUERY
    SELECT v_rows_variant;
END;
$$;


ALTER FUNCTION core.update_product_variant(p_id_producto integer, p_id_variante integer, p_sku text, p_imagenes jsonb, p_precio numeric, p_atributos jsonb) OWNER TO neondb_owner;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: attributes; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.attributes (
    id_atributo integer NOT NULL,
    nombre character varying(50) NOT NULL,
    id_padre integer
);


ALTER TABLE core.attributes OWNER TO neondb_owner;

--
-- Name: attributes_id_atributo_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.attributes ALTER COLUMN id_atributo ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.attributes_id_atributo_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: cart_items; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.cart_items (
    id_carrito integer NOT NULL,
    id_variante integer NOT NULL,
    cantidad integer NOT NULL,
    precio_unitario numeric(12,2) NOT NULL,
    CONSTRAINT cart_items_cantidad_check CHECK ((cantidad > 0))
);


ALTER TABLE core.cart_items OWNER TO neondb_owner;

--
-- Name: carts; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.carts (
    id_carrito integer NOT NULL,
    id_usuario integer,
    estado character varying(20) DEFAULT 'activo'::character varying,
    fecha_creacion timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE core.carts OWNER TO neondb_owner;

--
-- Name: carts_id_carrito_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.carts ALTER COLUMN id_carrito ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.carts_id_carrito_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: categories; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.categories (
    id_categoria integer NOT NULL,
    nombre character varying(50) NOT NULL,
    id_padre integer
);


ALTER TABLE core.categories OWNER TO neondb_owner;

--
-- Name: categories_id_categoria_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.categories ALTER COLUMN id_categoria ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.categories_id_categoria_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: direcciones; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.direcciones (
    id_direccion integer NOT NULL,
    id_usuario integer,
    alias character varying(50),
    calle character varying(150) NOT NULL,
    numero character varying(20),
    colonia character varying(100),
    ciudad character varying(100) NOT NULL,
    estado character varying(100) NOT NULL,
    codigo_postal character varying(10) NOT NULL,
    pais character varying(100) DEFAULT 'México'::character varying,
    principal boolean DEFAULT false,
    fecha_creacion timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE core.direcciones OWNER TO neondb_owner;

--
-- Name: direcciones_id_direccion_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.direcciones ALTER COLUMN id_direccion ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.direcciones_id_direccion_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: inventory; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.inventory (
    id_inventory integer NOT NULL,
    id_variante integer,
    stock_actual integer DEFAULT 0,
    costo_promedio numeric(12,2)
);


ALTER TABLE core.inventory OWNER TO neondb_owner;

--
-- Name: inventory_id_inventory_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.inventory ALTER COLUMN id_inventory ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.inventory_id_inventory_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: inventory_movements; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.inventory_movements (
    id_movimiento integer NOT NULL,
    id_variante integer,
    tipo character varying(20),
    cantidad integer NOT NULL,
    costo_unitario numeric(12,2),
    referencia_tipo character varying(50),
    referencia_id integer,
    fecha timestamp with time zone DEFAULT now()
);


ALTER TABLE core.inventory_movements OWNER TO neondb_owner;

--
-- Name: inventory_movements_id_movimiento_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.inventory_movements ALTER COLUMN id_movimiento ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.inventory_movements_id_movimiento_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: marcas; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.marcas (
    id_marca integer NOT NULL,
    nombre character varying(50) NOT NULL,
    imagen character varying(500)
);


ALTER TABLE core.marcas OWNER TO neondb_owner;

--
-- Name: marcas_id_marca_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.marcas ALTER COLUMN id_marca ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.marcas_id_marca_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: order_items; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.order_items (
    id_orden integer NOT NULL,
    id_variante integer NOT NULL,
    nombre_producto character varying(150) NOT NULL,
    sku character varying(50),
    cantidad integer NOT NULL,
    precio_unitario numeric(12,2) NOT NULL,
    total numeric(12,2) NOT NULL
);


ALTER TABLE core.order_items OWNER TO neondb_owner;

--
-- Name: orders; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.orders (
    id_orden integer NOT NULL,
    id_usuario integer,
    id_direccion_envio integer,
    estado character varying(30) DEFAULT 'pendiente'::character varying,
    subtotal numeric(12,2) NOT NULL,
    descuento numeric(12,2) DEFAULT 0,
    total numeric(12,2) NOT NULL,
    metodo_pago character varying(50),
    fecha_pago timestamp without time zone,
    fecha_envio timestamp without time zone,
    fecha_entrega timestamp without time zone,
    fecha_creacion timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE core.orders OWNER TO neondb_owner;

--
-- Name: orders_id_orden_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.orders ALTER COLUMN id_orden ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.orders_id_orden_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: pagos; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.pagos (
    id_pago integer NOT NULL,
    id_orden integer,
    proveedor_pago character varying(50),
    referencia_externa character varying(255),
    monto numeric(12,2),
    estado character varying(30),
    fecha_creacion timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE core.pagos OWNER TO neondb_owner;

--
-- Name: pagos_id_pago_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.pagos ALTER COLUMN id_pago ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.pagos_id_pago_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: product_variants; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.product_variants (
    id_variante integer NOT NULL,
    id_producto integer,
    sku character varying(50) NOT NULL,
    precio numeric(12,2) DEFAULT 0 NOT NULL,
    imagenes jsonb DEFAULT '[]'::jsonb,
    atributos jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE core.product_variants OWNER TO neondb_owner;

--
-- Name: product_variants_id_variante_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.product_variants ALTER COLUMN id_variante ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.product_variants_id_variante_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: products; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.products (
    id_producto integer NOT NULL,
    id_marca integer,
    id_categoria integer,
    nombre character varying(150) NOT NULL,
    descripcion text,
    activo boolean DEFAULT true,
    fecha_creacion timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE core.products OWNER TO neondb_owner;

--
-- Name: products_id_producto_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.products ALTER COLUMN id_producto ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.products_id_producto_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: reviews; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.reviews (
    id_review integer NOT NULL,
    id_producto integer,
    id_usuario integer,
    calificacion integer,
    comentario text,
    fecha timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT reviews_calificacion_check CHECK (((calificacion >= 1) AND (calificacion <= 5)))
);


ALTER TABLE core.reviews OWNER TO neondb_owner;

--
-- Name: reviews_id_review_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.reviews ALTER COLUMN id_review ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.reviews_id_review_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: roles; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.roles (
    id_rol integer NOT NULL,
    rol character varying(20)
);


ALTER TABLE core.roles OWNER TO neondb_owner;

--
-- Name: roles_id_rol_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.roles ALTER COLUMN id_rol ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.roles_id_rol_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: users; Type: TABLE; Schema: core; Owner: neondb_owner
--

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
    fecha_creacion timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    email_verified integer,
    telefono_verified integer,
    google_id character varying(255),
    ubicacion integer
);


ALTER TABLE core.users OWNER TO neondb_owner;

--
-- Name: users_id_usuario_seq; Type: SEQUENCE; Schema: core; Owner: neondb_owner
--

ALTER TABLE core.users ALTER COLUMN id_usuario ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME core.users_id_usuario_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: variant_attribute_values; Type: TABLE; Schema: core; Owner: neondb_owner
--

CREATE TABLE core.variant_attribute_values (
    id_variante integer NOT NULL,
    id_atributo integer NOT NULL,
    valor character varying(100) NOT NULL
);


ALTER TABLE core.variant_attribute_values OWNER TO neondb_owner;

--
-- Data for Name: attributes; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.attributes (id_atributo, nombre, id_padre) FROM stdin;
1	Talla	\N
2	Color	\N
3	Material	\N
10	Genero	\N
12	XS	1
13	S	1
14	M	1
15	L	1
16	XL	1
17	XXL	1
18	Negro	2
19	Blanco	2
20	Azul	2
21	Rojo	2
22	Gris	2
23	Verde	2
24	Algodón	3
25	Poliéster	3
26	Elastano	3
27	Nylon	3
28	Cuero sintético	3
29	Hombre	10
30	Mujer	10
31	Unisex	10
32	Niño	10
33	Niña	10
34	Tipo de tela	\N
35	Dry-Fit	34
36	Transpirable	34
37	Térmica	34
38	Impermeable	34
39	Malla deportiva	34
40	Deporte	\N
41	Fútbol	40
42	Running	40
43	Gimnasio	40
44	Ciclismo	40
45	Natación	40
46	Baloncesto	40
53	Rango de edad	\N
54	Bebé	53
55	Niños	53
56	Adolescente	53
57	Adulto	53
59	Cafe	2
\.


--
-- Data for Name: cart_items; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.cart_items (id_carrito, id_variante, cantidad, precio_unitario) FROM stdin;
\.


--
-- Data for Name: carts; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.carts (id_carrito, id_usuario, estado, fecha_creacion, fecha_actualizacion) FROM stdin;
\.


--
-- Data for Name: categories; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.categories (id_categoria, nombre, id_padre) FROM stdin;
4	Protección	2
5	Short	1
7	Deportes	\N
6	Pants	1
3	Playeras	1
27	Calzado	\N
28	Tenis	27
8	Gorras	2
14	Camisetas	1
1	Ropa	\N
2	Equipamiento	\N
\.


--
-- Data for Name: direcciones; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.direcciones (id_direccion, id_usuario, alias, calle, numero, colonia, ciudad, estado, codigo_postal, pais, principal, fecha_creacion) FROM stdin;
\.


--
-- Data for Name: inventory; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.inventory (id_inventory, id_variante, stock_actual, costo_promedio) FROM stdin;
38	64	2	0.00
46	72	5	0.00
42	68	10	0.00
48	75	4	0.00
41	67	3	0.00
44	70	4	0.00
49	76	3	0.00
35	63	5	0.00
50	77	0	0.00
51	78	0	0.00
53	80	0	0.00
54	81	10	0.00
31	58	2	0.00
36	62	3	0.00
39	65	5	0.00
43	69	0	0.00
45	71	3	0.00
47	74	3	0.00
40	66	6	0.00
\.


--
-- Data for Name: inventory_movements; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.inventory_movements (id_movimiento, id_variante, tipo, cantidad, costo_unitario, referencia_tipo, referencia_id, fecha) FROM stdin;
14	66	entrada	6	500.00	inventario_inicial	1069	2026-03-09 01:36:39.276833-06
4	58	entrada	2	1500.00	inventario_inicial	1002	2026-03-07 04:07:06-06
5	62	entrada	3	1000.00	inventario_inicial	1002	2026-03-07 13:04:07-06
6	63	entrada	2	1000.00	inventario_inicial	1002	2026-03-08 19:23:07.552931-06
11	65	entrada	5	500.00	inventario_inicial	1010	2026-03-08 20:13:35.965122-06
10	64	entrada	1	240.00	inventario_inicial	1008	2026-03-08 19:42:43.621563-06
12	71	entrada	3	300.00	inventario_inicial	1012	2026-03-08 20:36:32.346668-06
13	74	entrada	3	299.00	inventario_inicial	1046	2026-03-09 01:23:22.495043-06
15	64	entrada	1	600.00	compra	1086	2026-03-09 01:39:40.474783-06
16	72	entrada	5	470.00	inventario_inicial	1060	2026-03-09 01:42:55.034282-06
17	68	entrada	10	200.00	inventario_inicial	12345	2026-03-09 01:53:37.533468-06
18	75	entrada	4	240.00	inventario_inicial	1529	2026-03-09 01:56:36.934461-06
19	67	entrada	3	200.00	inventario_inicial	5379	2026-03-09 01:56:56.563789-06
20	70	entrada	4	588.00	inventario_inicial	3698	2026-03-09 02:00:47.320444-06
21	76	entrada	3	210.00	inventario_inicial	6532	2026-03-09 02:05:29.162807-06
22	63	entrada	3	250.00	compra	1349	2026-03-09 02:18:45.539304-06
23	81	entrada	10	300.00	inventario_inicial	1093	2026-03-10 02:44:53.499028-06
\.


--
-- Data for Name: marcas; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.marcas (id_marca, nombre, imagen) FROM stdin;
5	Pirma	https://imgs.search.brave.com/mDGb5uKTbe-vx_w3VP1-kV0UCVr4unxhC19pvaCKoU0/rs:fit:500:0:1:0/g:ce/aHR0cHM6Ly9jZG4u/YnJhbmRmZXRjaC5p/by9kb21haW4vcGly/bWEuY29tLm14L2Zh/bGxiYWNrL2xldHRl/cm1hcmsvdGhlbWUv/ZGFyay9oLzQwMC93/LzQwMC9pY29uP2M9/MWJmd3NtRUgyMHp6/RWZTTlRlZA
3	Puma	https://imgs.search.brave.com/HNZTLkDuET7ibXAsDWLVP9yi9dX1F2Rnf4osZAu1UvI/rs:fit:500:0:1:0/g:ce/aHR0cHM6Ly9zdGF0/aWMudmVjdGVlenku/Y29tL3N5c3RlbS9y/ZXNvdXJjZXMvdGh1/bWJuYWlscy8wMTAv/OTk0LzQzMS9zbWFs/bC9wdW1hLWxvZ28t/YmxhY2stc3ltYm9s/LXdpdGgtbmFtZS1j/bG90aGVzLWRlc2ln/bi1pY29uLWFic3Ry/YWN0LWZvb3RiYWxs/LWlsbHVzdHJhdGlv/bi13aXRoLXdoaXRl/LWJhY2tncm91bmQt/ZnJlZS12ZWN0b3Iu/anBn
2	Adidas	https://imgs.search.brave.com/gsVZwbr72you_zwx_-UObzbnM84pfbgn088VkrGyrH0/rs:fit:860:0:0:0/g:ce/aHR0cHM6Ly9icmFu/ZGVtaWEub3JnL2Nv/bnRlbmlkby9zdWJp/ZGFzLzIwMjIvMDQv/YWRpZGFzLTMtMTAy/NHg1NTEuanBn
4	Reebok	https://imgs.search.brave.com/SWTaRzCHQomCuZD6Ox4W6oeLLbkoVVMz5ARYLaKboMM/rs:fit:500:0:1:0/g:ce/aHR0cHM6Ly9zdGF0/aWMudmVjdGVlenku/Y29tL3N5c3RlbS9y/ZXNvdXJjZXMvdGh1/bWJuYWlscy8wMjMv/ODcxLzE2OS9zbWFs/bC9yZWVib2stbG9n/by1icmFuZC1jbG90/aGVzLXdpdGgtbmFt/ZS1ibGFjay1zeW1i/b2wtZGVzaWduLWlj/b24tYWJzdHJhY3Qt/aWxsdXN0cmF0aW9u/LWZyZWUtdmVjdG9y/LmpwZw
1	Nike	https://imgs.search.brave.com/1fPQhXA9kVIqlLnNqo_rHUwxC3s9cev7aHUhnRm5KPs/rs:fit:500:0:1:0/g:ce/aHR0cHM6Ly9jZG4u/d29ybGR2ZWN0b3Js/b2dvLmNvbS9sb2dv/cy9uaWtlLTMtMS5z/dmc
7	Voit	https://operadorapalermo.com.mx/wp-content/uploads/2020/09/VOIT1.png
\.


--
-- Data for Name: order_items; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.order_items (id_orden, id_variante, nombre_producto, sku, cantidad, precio_unitario, total) FROM stdin;
\.


--
-- Data for Name: orders; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.orders (id_orden, id_usuario, id_direccion_envio, estado, subtotal, descuento, total, metodo_pago, fecha_pago, fecha_envio, fecha_entrega, fecha_creacion) FROM stdin;
1	2	\N	pendiente	200.00	10.00	180.00	tarjeta	2026-03-19 00:00:00	2026-03-11 00:00:00	2026-03-10 00:00:00	2026-03-05 00:00:00
\.


--
-- Data for Name: pagos; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.pagos (id_pago, id_orden, proveedor_pago, referencia_externa, monto, estado, fecha_creacion) FROM stdin;
\.


--
-- Data for Name: product_variants; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.product_variants (id_variante, id_producto, sku, precio, imagenes, atributos) FROM stdin;
67	17	PL-PM-CF	500.00	["https://m.media-amazon.com/images/I/51GhO+NAidL._AC_SX679_.jpg", "https://m.media-amazon.com/images/I/514QCOYYiCL._AC_SX679_.jpg"]	{"Color": "Cafe", "Talla": "M", "Genero": "Hombre", "Material": "Algodón"}
77	36	GR-PM-NG	200.00	["https://http2.mlstatic.com/D_Q_NP_2X_794333-MLA100006964983_122025-F.webp", "https://http2.mlstatic.com/D_Q_NP_2X_713972-MLA93653698957_092025-F.webp"]	{"color": "negro", "talla": "M"}
78	24	PL-PM-NG	450.00	["https://http2.mlstatic.com/D_NQ_NP_2X_736985-MLM106811284577_022026-F-playera-puma-hombre-68470852-textil-negro.webp", "https://http2.mlstatic.com/D_NQ_NP_2X_623616-MLM90837878184_082025-F-playera-puma-hombre-68470852-textil-negro.webp", "https://http2.mlstatic.com/D_NQ_NP_2X_690053-MLM90837878190_082025-F-playera-puma-hombre-68470852-textil-negro.webp"]	{"Color": "Negro", "Talla": "M", "Genero": "Hombre", "Material": "Algodón"}
80	13	SH-NK-BL	600.00	["https://http2.mlstatic.com/D_NQ_NP_2X_624876-MLM106712071084_022026-F.webp"]	{"Color": "Blanco", "Talla": "M", "Genero": "Hombre"}
81	23	PL-PM-RJ-NA	400.00	["https://http2.mlstatic.com/D_NQ_NP_2X_870861-MLM90287195438_082025-F-playera-puma-x-hello-kitty-joven-63006215.webp", "https://http2.mlstatic.com/D_NQ_NP_2X_812142-MLM90287195436_082025-F-playera-puma-x-hello-kitty-joven-63006215.webp"]	{"Color": "Rojo", "Talla": "XS", "Genero": "Niña", "Rango de edad": "Niños"}
66	20	ESP-AD-BL	350.00	["https://m.media-amazon.com/images/I/61DaNpcP9gL._AC_SX569_.jpg", "https://m.media-amazon.com/images/I/41rmz2JT7vL._AC_SX569_.jpg"]	{"Color": "Blanco", "Talla": "M", "Deporte": "Fútbol"}
58	35	B-MV-BL	1700.00	["https://m.media-amazon.com/images/I/71VbDydpYBL._AC_SX569_.jpg", "https://m.media-amazon.com/images/I/71Gx6dV+3XL._AC_SX569_.jpg"]	{"Color": "Blanco", "Deporte": "Fútbol"}
64	33	B-PM-BL	260.00	["https://m.media-amazon.com/images/I/71OeNjrVwWL._AC_SX569_.jpg", "https://m.media-amazon.com/images/I/61O42qbLpQL._AC_SY550_.jpg"]	{"Color": "Blanco", "Deporte": "Fútbol", "Material": "Cuero sintético"}
62	34	SH-NK-NG	1100.00	["https://m.media-amazon.com/images/I/81B1UO-919L._AC_SX522_.jpg", "https://m.media-amazon.com/images/I/71R0A7MCx0L._AC_SX522_.jpg"]	{"Color": "Negro", "Talla": "L", "Genero": "Hombre"}
68	16	CL-NK-NG	300.00	["https://m.media-amazon.com/images/I/71eGJGhwcaL._AC_SX569_.jpg", "https://m.media-amazon.com/images/I/71eGJGhwcaL._AC_SX569_.jpg"]	{"Color": "Negro", "Talla": "M", "Genero": "Unisex", "Material": "Algodón"}
72	19	MQ-AD-NG	610.00	["https://m.media-amazon.com/images/I/51xp1zbCBNL._AC_SX569_.jpg", "https://m.media-amazon.com/images/I/613eIKQ48SL._AC_SX569_.jpg"]	{"Color": "Negro", "Talla": "L", "Genero": "Hombre"}
63	34	SH-NK-R	1100.00	["https://m.media-amazon.com/images/I/41YFErBmkKL._AC_SX342_.jpg", "https://m.media-amazon.com/images/I/31XdrvACDvL._AC_SX385_.jpg"]	{"Color": "Rojo", "Talla": "L", "Genero": "Hombre"}
70	2	ESP-AD-AZ	350.00	["https://m.media-amazon.com/images/I/61hFI30fcTL._AC_SX569_.jpg", "https://m.media-amazon.com/images/I/51fTg7QY9OL._AC_SX569_.jpg"]	{"Color": "Azul", "Talla": "M", "Deporte": "Fútbol"}
69	5	PL-NK-CF	700.00	["https://m.media-amazon.com/images/I/4107A+i7MmL._AC_SY741_.jpg", "https://m.media-amazon.com/images/I/41z1SHcZeXL._AC_SY500_.jpg"]	{"Color": "Cafe", "Talla": "M", "Genero": "Hombre"}
74	21	GR-NK-BL	600.00	["https://m.media-amazon.com/images/I/51YnGl4-HUL._AC_SX679_.jpg", "https://m.media-amazon.com/images/I/51i0zzrLC6L._AC_SX679_.jpg"]	{"Color": "Blanco", "Talla": "L", "Genero": "Unisex"}
76	30	PL-PM-BL	250.00	["https://m.media-amazon.com/images/I/51wyeD25KwL._AC_SX679_.jpg", "https://m.media-amazon.com/images/I/415bg1cXE3L._AC_SX679_.jpg"]	{"Color": "Blanco", "Talla": "S", "Genero": "Niño", "Material": "Algodón", "Rango de edad": "Niños"}
65	1	PL-NK-AZ	552.00	["https://m.media-amazon.com/images/I/511stkPNkLL._AC_SY500_.jpg", "https://m.media-amazon.com/images/I/512XxsqWM5L._AC_SY500_.jpg"]	{"Color": "Azul", "Talla": "L", "Genero": "Hombre", "Material": "Algodón"}
71	26	PL-PM-AZ	450.00	["https://m.media-amazon.com/images/I/71TVLHkl+GL._AC_SX425_.jpg", "https://m.media-amazon.com/images/I/71TVLHkl+GL._AC_SX425_.jpg"]	{"Color": "Azul", "Talla": "XS", "Genero": "Unisex", "Material": "Algodón", "Rango de edad": "Niños"}
75	12	SH-PM-NG	270.00	["https://m.media-amazon.com/images/I/714iwFbPcRL._AC_UL480_FMwebp_QL65_.jpg", "https://m.media-amazon.com/images/I/619iVJg+XKL._AC_SX569_.jpg"]	{"Color": "Negro", "Talla": "L", "Genero": "Hombre", "Deporte": "Running"}
\.


--
-- Data for Name: products; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.products (id_producto, id_marca, id_categoria, nombre, descripcion, activo, fecha_creacion, fecha_actualizacion) FROM stdin;
4	1	3	Nike Phantom Elite	Playera profesional de alto rendimiento	f	2026-02-18 22:35:11.987181	2026-02-19 04:35:11.987181
11	1	5	Short color azul	Descripcion	f	2026-02-22 18:19:14.486749	2026-02-23 00:19:14.486749
24	3	3	Playera puma color negra	Es una playera negra	f	2026-02-26 01:01:13.147324	2026-02-26 07:01:13.147324
5	1	3	Nike Phantom Elite Color Cafe	Playera profesional de alto rendimiento	f	2026-03-03 02:30:57.37305	2026-03-03 08:30:57.37305
3	1	3	Nike Air Zoom	Playera deportiva ligera	t	2026-02-26 02:36:28.336313	2026-02-26 08:36:28.336313
35	7	7	Balón de futbol marca voit	Balón oficial de la Liga MX. Calidad FIFA Quality Pro. Tecnología de construcción termo adherido. Número 5, tamaño y peso oficial.	t	2026-03-08 17:31:05.993444	2026-03-08 23:31:05.993444
34	1	5	Short deportivo para hombre marca nike	Es un short deportivo de la marca nike de buena calidad	t	2026-03-08 19:24:40.318283	2026-03-09 01:24:40.318283
12	3	5	Short para correr	Es un short para correr	t	2026-02-20 10:39:37.54414	2026-03-09 01:58:33.520593
33	3	7	Balón de futbol marca puma	Es un balon pa jugar fulbo	t	2026-03-03 19:38:15.246904	2026-03-09 02:07:37.37716
2	2	4	Espinilleras Adidas Ghost Graphic	Espinilleras de fútbol con placa rígida	t	2026-02-28 23:06:04.154061	2026-03-09 02:01:29.817964
30	3	3	Playera puma para niños color blanca	Es una playera puma pa niños	t	2026-02-26 01:36:32.297056	2026-02-26 07:36:32.297056
26	3	3	Playera puma para niños color azul	es una playera puma	t	2026-02-26 01:15:17.019497	2026-02-26 07:15:17.019497
13	1	5	Short marca puma pa jugar	Es un short comodo pa jugar fulbo	f	2026-02-20 10:44:49.014676	2026-02-20 16:44:49.014676
17	3	3	Playera  puma color cafe	Es una playera color cafe para hacer deporte	t	2026-03-03 02:35:05.317762	2026-03-09 22:56:29.264185
21	1	8	Gorra blanca nike	Es una gorra blanca	t	2026-02-23 16:58:30.197527	2026-02-23 22:58:30.197527
19	2	4	Muñequeras color negro marca adidas	Son unas muñequeras de buena calidad, marca nike para hombres	t	2026-02-22 18:16:55.588534	2026-03-09 01:44:49.020543
20	4	4	Espinilleras color negro	SON UNAS ESPINILLERAS	t	2026-03-03 02:35:47.766452	2026-03-03 08:35:47.766452
16	4	1	Calcetines negros	Calcetines comodos para hacer deporte, en color negro	t	2026-03-03 02:33:52.38351	2026-03-03 08:33:52.38351
36	3	8	Gorra marca puma color negro	Gorra marca puma en colo negro de muy buena calidad	f	2026-03-10 01:10:00.323998	2026-03-10 01:10:00.323998
23	3	3	Playera deportiva para niña marca puma	Es una playera roja puma para genero niña	t	2026-02-23 17:34:43.387539	2026-02-23 23:34:43.387539
1	1	3	Playera marca Nike en color azulito	Es una playera deportiva marca Nike de color azul	t	2026-03-08 03:00:00.166955	2026-03-10 17:44:33.207053
\.


--
-- Data for Name: reviews; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.reviews (id_review, id_producto, id_usuario, calificacion, comentario, fecha) FROM stdin;
\.


--
-- Data for Name: roles; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.roles (id_rol, rol) FROM stdin;
1	Usuario
2	Empleado
3	Administrador
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.users (id_usuario, nombre, "aPaterno", "aMaterno", email, telefono, passw, rol, activo, token_verificacion, token_expiracion, intentos_token, fecha_creacion, fecha_actualizacion, email_verified, telefono_verified, google_id, ubicacion) FROM stdin;
2	Pedrito	Mendez	Midford	usuariotest1@gmail.com	5356789765	$2b$10$xlFhCqD1T/9jwFOQxT11puqazuiVKP1WKSA.OcGtFxrvBX06S8PBS	1	0	880483	2026-02-14 19:17:38.586	3	2026-02-13 19:17:38.586	2026-02-14 01:17:42.80115	0	\N	\N	\N
11	alexis	hernandez		alexishernandezgt05@gmail.com	\N	$2b$10$8FIrvR.1EZheJNiSMXA4auFkd8/oPeqG83Ld2AtXeY4.oEVIKdIjW	2	1		\N	\N	2026-03-04 22:15:28.034	2026-03-05 04:15:30.619593	1	\N	101734655057368957815	\N
10	ALEXIS YAZIR	HERNANDEZ	HIPOLITO	20230060@uthh.edu.mx	\N	$2b$10$e9M9C2kLkY6YPJYf1DOJiOclMqZo4aw/1cWrDXVlndq6xWi8YH6g6	1	1		\N	0	2026-03-04 22:14:03.202	2026-03-05 04:14:05.762375	1	\N	114847621552512941352	\N
5	Janne	Akenes	FLores	jannette999@gmail.com	1234567890	$2b$10$ay/q5iA4zxWH5ucXh.k0JOTXkK/VZqsCmTPMqTFEgopM7Ced/kU/q	1	0	638370	2026-03-04 05:00:46.79	3	2026-02-20 12:44:23.933	2026-02-20 18:44:25.676597	0	\N	\N	\N
8	Sport Admin	Admin	Admin	sportcentersoporte@gmail.com	3723452467	$2b$10$g121XV761WyDk6XoztuvFOfxB8b/wKtKYpFv96I4nTwrO5CPFF732	3	1		\N	0	2026-02-23 01:05:23.71	2026-02-23 01:05:23.714523	1	\N	100588603343195401757	\N
1	Yazir	Hdez	Hdez	alexisyazirh@gmail.com	7712315167	$2b$10$ooMNvAn06Mla7AluepZ1BuEZbgRDLRwWUtnQxdeIMjZOyl/Q6RxXm	3	1		\N	0	2026-02-02 20:33:27.727	2026-03-09 04:26:25.841	1	\N	103371344045852970836	\N
\.


--
-- Data for Name: variant_attribute_values; Type: TABLE DATA; Schema: core; Owner: neondb_owner
--

COPY core.variant_attribute_values (id_variante, id_atributo, valor) FROM stdin;
58	2	Blanco
58	40	Fútbol
63	2	Rojo
63	10	Hombre
62	10	Hombre
62	1	L
63	1	L
62	2	Negro
64	3	Cuero sintético
64	40	Fútbol
64	2	Blanco
65	1	XL
65	2	Azul
65	10	Hombre
65	3	Algodón
66	40	Fútbol
66	2	Blanco
66	1	M
67	2	Cafe
67	3	Algodón
67	1	M
67	10	Hombre
68	1	M
68	10	Unisex
68	3	Algodón
68	2	Negro
69	1	M
69	10	Hombre
69	2	Cafe
70	40	Fútbol
70	1	M
70	2	Azul
71	1	XS
71	10	Unisex
71	53	Niños
71	3	Algodón
71	2	Azul
72	10	Hombre
72	2	Negro
72	1	L
75	40	Running
75	2	Negro
75	1	L
75	10	Hombre
74	1	L
74	2	Blanco
74	10	Unisex
76	2	Blanco
76	53	Niños
76	3	Algodón
76	10	Niño
76	1	S
\.


--
-- Name: attributes_id_atributo_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.attributes_id_atributo_seq', 59, true);


--
-- Name: carts_id_carrito_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.carts_id_carrito_seq', 1, false);


--
-- Name: categories_id_categoria_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.categories_id_categoria_seq', 32, true);


--
-- Name: direcciones_id_direccion_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.direcciones_id_direccion_seq', 1, false);


--
-- Name: inventory_id_inventory_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.inventory_id_inventory_seq', 54, true);


--
-- Name: inventory_movements_id_movimiento_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.inventory_movements_id_movimiento_seq', 23, true);


--
-- Name: marcas_id_marca_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.marcas_id_marca_seq', 7, true);


--
-- Name: orders_id_orden_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.orders_id_orden_seq', 1, true);


--
-- Name: pagos_id_pago_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.pagos_id_pago_seq', 1, false);


--
-- Name: product_variants_id_variante_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.product_variants_id_variante_seq', 81, true);


--
-- Name: products_id_producto_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.products_id_producto_seq', 36, true);


--
-- Name: reviews_id_review_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.reviews_id_review_seq', 1, false);


--
-- Name: roles_id_rol_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.roles_id_rol_seq', 3, true);


--
-- Name: users_id_usuario_seq; Type: SEQUENCE SET; Schema: core; Owner: neondb_owner
--

SELECT pg_catalog.setval('core.users_id_usuario_seq', 11, true);


--
-- Name: attributes attributes_nombre_key; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.attributes
    ADD CONSTRAINT attributes_nombre_key UNIQUE (nombre);


--
-- Name: attributes attributes_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.attributes
    ADD CONSTRAINT attributes_pkey PRIMARY KEY (id_atributo);


--
-- Name: cart_items cart_items_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.cart_items
    ADD CONSTRAINT cart_items_pkey PRIMARY KEY (id_carrito, id_variante);


--
-- Name: carts carts_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.carts
    ADD CONSTRAINT carts_pkey PRIMARY KEY (id_carrito);


--
-- Name: categories categories_nombre_key; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.categories
    ADD CONSTRAINT categories_nombre_key UNIQUE (nombre);


--
-- Name: categories categories_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.categories
    ADD CONSTRAINT categories_pkey PRIMARY KEY (id_categoria);


--
-- Name: direcciones direcciones_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.direcciones
    ADD CONSTRAINT direcciones_pkey PRIMARY KEY (id_direccion);


--
-- Name: inventory inventory_id_variante_key; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.inventory
    ADD CONSTRAINT inventory_id_variante_key UNIQUE (id_variante);


--
-- Name: inventory_movements inventory_movements_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.inventory_movements
    ADD CONSTRAINT inventory_movements_pkey PRIMARY KEY (id_movimiento);


--
-- Name: inventory inventory_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.inventory
    ADD CONSTRAINT inventory_pkey PRIMARY KEY (id_inventory);


--
-- Name: marcas marcas_nombre_key; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.marcas
    ADD CONSTRAINT marcas_nombre_key UNIQUE (nombre);


--
-- Name: marcas marcas_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.marcas
    ADD CONSTRAINT marcas_pkey PRIMARY KEY (id_marca);


--
-- Name: order_items order_items_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.order_items
    ADD CONSTRAINT order_items_pkey PRIMARY KEY (id_orden, id_variante);


--
-- Name: orders orders_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (id_orden);


--
-- Name: pagos pagos_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.pagos
    ADD CONSTRAINT pagos_pkey PRIMARY KEY (id_pago);


--
-- Name: product_variants product_variants_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.product_variants
    ADD CONSTRAINT product_variants_pkey PRIMARY KEY (id_variante);


--
-- Name: product_variants product_variants_sku_key; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.product_variants
    ADD CONSTRAINT product_variants_sku_key UNIQUE (sku);


--
-- Name: products products_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.products
    ADD CONSTRAINT products_pkey PRIMARY KEY (id_producto);


--
-- Name: reviews reviews_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.reviews
    ADD CONSTRAINT reviews_pkey PRIMARY KEY (id_review);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id_rol);


--
-- Name: attributes uq_attributes_nombre_padre; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.attributes
    ADD CONSTRAINT uq_attributes_nombre_padre UNIQUE (nombre, id_padre);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id_usuario);


--
-- Name: variant_attribute_values variant_attribute_values_pkey; Type: CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.variant_attribute_values
    ADD CONSTRAINT variant_attribute_values_pkey PRIMARY KEY (id_variante, id_atributo);


--
-- Name: product_variants trg_create_inventory_after_variant; Type: TRIGGER; Schema: core; Owner: neondb_owner
--

CREATE TRIGGER trg_create_inventory_after_variant AFTER INSERT ON core.product_variants FOR EACH ROW EXECUTE FUNCTION core.create_inventory_after_variant();


--
-- Name: cart_items cart_items_id_carrito_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.cart_items
    ADD CONSTRAINT cart_items_id_carrito_fkey FOREIGN KEY (id_carrito) REFERENCES core.carts(id_carrito) ON DELETE CASCADE;


--
-- Name: cart_items cart_items_id_variante_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.cart_items
    ADD CONSTRAINT cart_items_id_variante_fkey FOREIGN KEY (id_variante) REFERENCES core.product_variants(id_variante);


--
-- Name: carts carts_id_usuario_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.carts
    ADD CONSTRAINT carts_id_usuario_fkey FOREIGN KEY (id_usuario) REFERENCES core.users(id_usuario) ON DELETE CASCADE;


--
-- Name: categories categories_id_padre_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.categories
    ADD CONSTRAINT categories_id_padre_fkey FOREIGN KEY (id_padre) REFERENCES core.categories(id_categoria);


--
-- Name: direcciones direcciones_id_usuario_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.direcciones
    ADD CONSTRAINT direcciones_id_usuario_fkey FOREIGN KEY (id_usuario) REFERENCES core.users(id_usuario) ON DELETE CASCADE;


--
-- Name: attributes fk_attributes_parent; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.attributes
    ADD CONSTRAINT fk_attributes_parent FOREIGN KEY (id_padre) REFERENCES core.attributes(id_atributo) ON DELETE CASCADE;


--
-- Name: users fk_users_roles; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.users
    ADD CONSTRAINT fk_users_roles FOREIGN KEY (rol) REFERENCES core.roles(id_rol);


--
-- Name: inventory inventory_id_variante_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.inventory
    ADD CONSTRAINT inventory_id_variante_fkey FOREIGN KEY (id_variante) REFERENCES core.product_variants(id_variante);


--
-- Name: inventory_movements inventory_movements_id_variante_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.inventory_movements
    ADD CONSTRAINT inventory_movements_id_variante_fkey FOREIGN KEY (id_variante) REFERENCES core.product_variants(id_variante);


--
-- Name: order_items order_items_id_orden_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.order_items
    ADD CONSTRAINT order_items_id_orden_fkey FOREIGN KEY (id_orden) REFERENCES core.orders(id_orden) ON DELETE CASCADE;


--
-- Name: order_items order_items_id_variante_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.order_items
    ADD CONSTRAINT order_items_id_variante_fkey FOREIGN KEY (id_variante) REFERENCES core.product_variants(id_variante);


--
-- Name: orders orders_id_direccion_envio_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.orders
    ADD CONSTRAINT orders_id_direccion_envio_fkey FOREIGN KEY (id_direccion_envio) REFERENCES core.direcciones(id_direccion);


--
-- Name: orders orders_id_usuario_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.orders
    ADD CONSTRAINT orders_id_usuario_fkey FOREIGN KEY (id_usuario) REFERENCES core.users(id_usuario);


--
-- Name: pagos pagos_id_orden_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.pagos
    ADD CONSTRAINT pagos_id_orden_fkey FOREIGN KEY (id_orden) REFERENCES core.orders(id_orden) ON DELETE CASCADE;


--
-- Name: product_variants product_variants_id_producto_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.product_variants
    ADD CONSTRAINT product_variants_id_producto_fkey FOREIGN KEY (id_producto) REFERENCES core.products(id_producto) ON DELETE CASCADE;


--
-- Name: products products_id_categoria_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.products
    ADD CONSTRAINT products_id_categoria_fkey FOREIGN KEY (id_categoria) REFERENCES core.categories(id_categoria) ON DELETE SET NULL;


--
-- Name: products products_id_marca_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.products
    ADD CONSTRAINT products_id_marca_fkey FOREIGN KEY (id_marca) REFERENCES core.marcas(id_marca) ON DELETE CASCADE;


--
-- Name: reviews reviews_id_producto_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.reviews
    ADD CONSTRAINT reviews_id_producto_fkey FOREIGN KEY (id_producto) REFERENCES core.products(id_producto) ON DELETE CASCADE;


--
-- Name: reviews reviews_id_usuario_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.reviews
    ADD CONSTRAINT reviews_id_usuario_fkey FOREIGN KEY (id_usuario) REFERENCES core.users(id_usuario);


--
-- Name: variant_attribute_values variant_attribute_values_id_atributo_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.variant_attribute_values
    ADD CONSTRAINT variant_attribute_values_id_atributo_fkey FOREIGN KEY (id_atributo) REFERENCES core.attributes(id_atributo);


--
-- Name: variant_attribute_values variant_attribute_values_id_variante_fkey; Type: FK CONSTRAINT; Schema: core; Owner: neondb_owner
--

ALTER TABLE ONLY core.variant_attribute_values
    ADD CONSTRAINT variant_attribute_values_id_variante_fkey FOREIGN KEY (id_variante) REFERENCES core.product_variants(id_variante) ON DELETE CASCADE;


--
-- Name: SCHEMA core; Type: ACL; Schema: -; Owner: neondb_owner
--

GRANT ALL ON SCHEMA core TO app_admin;
GRANT USAGE ON SCHEMA core TO app_editor;
GRANT USAGE ON SCHEMA core TO app_reader;
GRANT USAGE ON SCHEMA core TO app_backup;


--
-- Name: FUNCTION create_inventory_after_variant(); Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT ALL ON FUNCTION core.create_inventory_after_variant() TO app_backup;


--
-- Name: FUNCTION create_inventory_movement(p_id_variante integer, p_tipo text, p_cantidad integer, p_costo_unitario numeric, p_referencia_tipo text, p_referencia_id integer); Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT ALL ON FUNCTION core.create_inventory_movement(p_id_variante integer, p_tipo text, p_cantidad integer, p_costo_unitario numeric, p_referencia_tipo text, p_referencia_id integer) TO app_backup;


--
-- Name: FUNCTION get_all_products(); Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT ALL ON FUNCTION core.get_all_products() TO app_backup;


--
-- Name: FUNCTION get_inventory_products(); Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT ALL ON FUNCTION core.get_inventory_products() TO app_backup;


--
-- Name: FUNCTION get_products_with_variants_without_attributes(); Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT ALL ON FUNCTION core.get_products_with_variants_without_attributes() TO app_backup;


--
-- Name: FUNCTION get_recients_products(); Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT ALL ON FUNCTION core.get_recients_products() TO app_backup;


--
-- Name: FUNCTION get_recients_users(); Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT ALL ON FUNCTION core.get_recients_users() TO app_backup;


--
-- Name: FUNCTION get_variants_product_by_id(id_producto_p integer); Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT ALL ON FUNCTION core.get_variants_product_by_id(id_producto_p integer) TO app_backup;


--
-- Name: FUNCTION update_full_product(p_id_producto integer, p_id_marca integer, p_id_categoria integer, p_nombre text, p_descripcion text); Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT ALL ON FUNCTION core.update_full_product(p_id_producto integer, p_id_marca integer, p_id_categoria integer, p_nombre text, p_descripcion text) TO app_backup;


--
-- Name: FUNCTION update_product_variant(p_id_producto integer, p_id_variante integer, p_sku text, p_imagenes jsonb, p_precio numeric, p_atributos jsonb); Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT ALL ON FUNCTION core.update_product_variant(p_id_producto integer, p_id_variante integer, p_sku text, p_imagenes jsonb, p_precio numeric, p_atributos jsonb) TO app_backup;


--
-- Name: TABLE attributes; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.attributes TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.attributes TO app_editor;
GRANT ALL ON TABLE core.attributes TO app_admin;
GRANT SELECT ON TABLE core.attributes TO app_backup;


--
-- Name: SEQUENCE attributes_id_atributo_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.attributes_id_atributo_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.attributes_id_atributo_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.attributes_id_atributo_seq TO app_backup;


--
-- Name: TABLE cart_items; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.cart_items TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.cart_items TO app_editor;
GRANT ALL ON TABLE core.cart_items TO app_admin;
GRANT SELECT ON TABLE core.cart_items TO app_backup;


--
-- Name: TABLE carts; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.carts TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.carts TO app_editor;
GRANT ALL ON TABLE core.carts TO app_admin;
GRANT SELECT ON TABLE core.carts TO app_backup;


--
-- Name: SEQUENCE carts_id_carrito_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.carts_id_carrito_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.carts_id_carrito_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.carts_id_carrito_seq TO app_backup;


--
-- Name: TABLE categories; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.categories TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.categories TO app_editor;
GRANT ALL ON TABLE core.categories TO app_admin;
GRANT SELECT ON TABLE core.categories TO app_backup;


--
-- Name: SEQUENCE categories_id_categoria_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.categories_id_categoria_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.categories_id_categoria_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.categories_id_categoria_seq TO app_backup;


--
-- Name: TABLE direcciones; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.direcciones TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.direcciones TO app_editor;
GRANT ALL ON TABLE core.direcciones TO app_admin;
GRANT SELECT ON TABLE core.direcciones TO app_backup;


--
-- Name: SEQUENCE direcciones_id_direccion_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.direcciones_id_direccion_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.direcciones_id_direccion_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.direcciones_id_direccion_seq TO app_backup;


--
-- Name: TABLE inventory; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT ALL ON TABLE core.inventory TO app_admin;
GRANT SELECT,INSERT,UPDATE ON TABLE core.inventory TO app_editor;
GRANT SELECT ON TABLE core.inventory TO app_reader;
GRANT SELECT ON TABLE core.inventory TO app_backup;


--
-- Name: SEQUENCE inventory_id_inventory_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.inventory_id_inventory_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.inventory_id_inventory_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.inventory_id_inventory_seq TO app_backup;


--
-- Name: TABLE inventory_movements; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT ALL ON TABLE core.inventory_movements TO app_admin;
GRANT SELECT,INSERT,UPDATE ON TABLE core.inventory_movements TO app_editor;
GRANT SELECT ON TABLE core.inventory_movements TO app_reader;
GRANT SELECT ON TABLE core.inventory_movements TO app_backup;


--
-- Name: SEQUENCE inventory_movements_id_movimiento_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.inventory_movements_id_movimiento_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.inventory_movements_id_movimiento_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.inventory_movements_id_movimiento_seq TO app_backup;


--
-- Name: TABLE marcas; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.marcas TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.marcas TO app_editor;
GRANT ALL ON TABLE core.marcas TO app_admin;
GRANT SELECT ON TABLE core.marcas TO app_backup;


--
-- Name: SEQUENCE marcas_id_marca_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.marcas_id_marca_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.marcas_id_marca_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.marcas_id_marca_seq TO app_backup;


--
-- Name: TABLE order_items; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.order_items TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.order_items TO app_editor;
GRANT ALL ON TABLE core.order_items TO app_admin;
GRANT SELECT ON TABLE core.order_items TO app_backup;


--
-- Name: TABLE orders; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.orders TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.orders TO app_editor;
GRANT ALL ON TABLE core.orders TO app_admin;
GRANT SELECT ON TABLE core.orders TO app_backup;


--
-- Name: SEQUENCE orders_id_orden_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.orders_id_orden_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.orders_id_orden_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.orders_id_orden_seq TO app_backup;


--
-- Name: TABLE pagos; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.pagos TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.pagos TO app_editor;
GRANT ALL ON TABLE core.pagos TO app_admin;
GRANT SELECT ON TABLE core.pagos TO app_backup;


--
-- Name: SEQUENCE pagos_id_pago_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.pagos_id_pago_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.pagos_id_pago_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.pagos_id_pago_seq TO app_backup;


--
-- Name: TABLE product_variants; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.product_variants TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.product_variants TO app_editor;
GRANT ALL ON TABLE core.product_variants TO app_admin;
GRANT SELECT ON TABLE core.product_variants TO app_backup;


--
-- Name: SEQUENCE product_variants_id_variante_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.product_variants_id_variante_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.product_variants_id_variante_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.product_variants_id_variante_seq TO app_backup;


--
-- Name: TABLE products; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.products TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.products TO app_editor;
GRANT ALL ON TABLE core.products TO app_admin;
GRANT SELECT ON TABLE core.products TO app_backup;


--
-- Name: SEQUENCE products_id_producto_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.products_id_producto_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.products_id_producto_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.products_id_producto_seq TO app_backup;


--
-- Name: TABLE reviews; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.reviews TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.reviews TO app_editor;
GRANT ALL ON TABLE core.reviews TO app_admin;
GRANT SELECT ON TABLE core.reviews TO app_backup;


--
-- Name: SEQUENCE reviews_id_review_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.reviews_id_review_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.reviews_id_review_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.reviews_id_review_seq TO app_backup;


--
-- Name: TABLE roles; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.roles TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.roles TO app_editor;
GRANT ALL ON TABLE core.roles TO app_admin;
GRANT SELECT ON TABLE core.roles TO app_backup;


--
-- Name: SEQUENCE roles_id_rol_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.roles_id_rol_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.roles_id_rol_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.roles_id_rol_seq TO app_backup;


--
-- Name: TABLE users; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.users TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.users TO app_editor;
GRANT ALL ON TABLE core.users TO app_admin;
GRANT SELECT ON TABLE core.users TO app_backup;


--
-- Name: SEQUENCE users_id_usuario_seq; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT,USAGE ON SEQUENCE core.users_id_usuario_seq TO app_admin;
GRANT SELECT,USAGE ON SEQUENCE core.users_id_usuario_seq TO app_editor;
GRANT SELECT ON SEQUENCE core.users_id_usuario_seq TO app_backup;


--
-- Name: TABLE variant_attribute_values; Type: ACL; Schema: core; Owner: neondb_owner
--

GRANT SELECT ON TABLE core.variant_attribute_values TO app_reader;
GRANT SELECT,INSERT,UPDATE ON TABLE core.variant_attribute_values TO app_editor;
GRANT ALL ON TABLE core.variant_attribute_values TO app_admin;
GRANT SELECT ON TABLE core.variant_attribute_values TO app_backup;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: core; Owner: neondb_owner
--

ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA core GRANT SELECT,USAGE ON SEQUENCES TO app_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA core GRANT SELECT,USAGE ON SEQUENCES TO app_editor;
ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA core GRANT SELECT ON SEQUENCES TO app_backup;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: core; Owner: neondb_owner
--

ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA core GRANT ALL ON TABLES TO app_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA core GRANT SELECT,INSERT,UPDATE ON TABLES TO app_editor;
ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA core GRANT SELECT ON TABLES TO app_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA core GRANT SELECT ON TABLES TO app_backup;


--
-- PostgreSQL database dump complete
--

\unrestrict ecpACbvzzocHOrxo3zW0QGHja0FUZ1YawvCNVK0v8fy0TDNEXbtW6kxhE9Zi9Sa

