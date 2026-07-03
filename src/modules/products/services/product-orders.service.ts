/* eslint-disable */
import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { randomBytes } from 'crypto';
import { DataSource, Repository } from 'typeorm';

import { UpdateShipmentDto } from '../dto/orders/update-shipment.dto';
import {
  CreateReturnDto,
  UpdateReturnStatusDto,
} from '../dto/returns/create-return.dto';
import { Orders } from '../entities/orders/orders.entity';
import { MailService } from '../../../services/mail/mail.service';

@Injectable()
export class ProductOrdersService {
  private readonly logger = new Logger(ProductOrdersService.name);

  constructor(
    @InjectDataSource('readerConnection')
    private readonly readerDataSource: DataSource,
    @InjectDataSource('editorConnection')
    private readonly editorDataSource: DataSource,
    @InjectRepository(Orders, 'editorConnection')
    private readonly ordersEditorRepository: Repository<Orders>,
    @InjectRepository(Orders, 'readerConnection')
    private readonly ordersReaderRepository: Repository<Orders>,
    private readonly mailService: MailService,
  ) {}

  async getOrderDetail(id: number): Promise<any[]> {
    try {
      const result = await this.readerDataSource.query(
        `SELECT 
              o.id_orden,
              o.fecha_entrega as fecha_creacion,
              oi.cantidad, 
              oi.total
        FROM core.orders o
        JOIN core.order_items oi 
              ON oi.id_orden = o.id_orden
        JOIN core.product_variants v 
              ON v.id_variante = oi.id_variante
        WHERE v.id_producto = $1
        ORDER BY o.fecha_creacion;`,
        [id],
      );
      return result;
    } catch (error) {
      this.logger.error('Error al cargar los detalles de venta: ', error);
      throw error;
    }
  }

  async getAllOrders(): Promise<any[]> {
    const result = await this.readerDataSource.query(
      `
        SELECT 
            p.id_producto,
            p.nombre,

            c.nombre AS categoria,
            cp.nombre AS categoria_padre,

            COALESCE(d.deportes, '[]') AS deportes,
            COALESCE(img.imagenes, '[]') AS imagenes,

            v.total_vendido,
            v.ingresos_totales

        FROM core.products p

        LEFT JOIN core.categories c 
            ON c.id_categoria = p.id_categoria

        LEFT JOIN core.categories cp 
            ON cp.id_categoria = c.id_padre

        -- SOLO productos con ventas
        INNER JOIN (
            SELECT 
                v.id_producto,
                SUM(oi.cantidad) AS total_vendido,
                SUM(oi.total) AS ingresos_totales
            FROM core.product_variants v
            INNER JOIN core.order_items oi 
                ON oi.id_variante = v.id_variante
            GROUP BY v.id_producto
        ) v ON v.id_producto = p.id_producto

        -- deportes
        LEFT JOIN (
            SELECT 
                pd.id_producto,
                jsonb_agg(DISTINCT d.nombre) AS deportes
            FROM core.product_deportes pd
            JOIN core.deportes d 
                ON d.id_deporte = pd.id_deporte
            GROUP BY pd.id_producto
        ) d ON d.id_producto = p.id_producto

        -- imagenes
        LEFT JOIN (
            SELECT 
                v.id_producto,
                jsonb_agg(DISTINCT v.imagenes) AS imagenes
            FROM core.product_variants v
            GROUP BY v.id_producto
        ) img ON img.id_producto = p.id_producto

        WHERE p.activo = TRUE

        ORDER BY v.total_vendido DESC;
      `,
    );

    return result;
  }

  async getOrderss(): Promise<Orders[]> {
    return await this.ordersReaderRepository.find();
  }

  async getEmployeeOrders(): Promise<any[]> {
    return await this.readerDataSource.query(`
      SELECT
        o.id_orden,
        o.id_usuario,
        o.id_direccion_envio,
        o.estado,
        o.subtotal,
        o.descuento,
        o.total,
        o.metodo_pago,
        o.fecha_pago,
        o.fecha_envio,
        o.fecha_entrega,
        o.fecha_creacion,
        s.id_envio,
        s.estado AS estado_envio,
        s.numero_guia AS tracking_number,
        s.paqueteria,
        s.costo_envio,
        s.fecha_entrega_estimada,
        s.fecha_entrega AS fecha_entrega_real,
        s.codigo_confirmacion_entrega,
        s.codigo_confirmacion_generado_en,
        s.entrega_confirmada_por_usuario,
        s.entrega_confirmada_en,
        s.entrega_validada_por_empleado,
        s.entrega_validada_en,
        COALESCE(ev.eventos, '[]'::jsonb) AS eventos_envio,
        jsonb_build_object(
          'calle', d.calle,
          'numero', d.numero,
          'colonia', d.colonia,
          'ciudad', d.ciudad,
          'estado', d.estado,
          'codigo_postal', d.codigo_postal,
          'pais', d.pais
        ) AS direccion_envio,
        COALESCE(
          NULLIF(TRIM(CONCAT_WS(' ', u.nombre, u."aPaterno", u."aMaterno")), ''),
          'Usuario'
        ) AS cliente,
        u.email,
        COALESCE(SUM(oi.cantidad), 0)::int AS total_productos,
        COALESCE(COUNT(oi.id_variante), 0)::int AS total_items,
        COALESCE(
          jsonb_agg(
            jsonb_build_object(
              'id_variante', oi.id_variante,
              'sku', COALESCE(oi.sku, pv.sku),
              'cantidad', oi.cantidad,
              'precio_unitario', oi.precio_unitario,
              'total', oi.total,
              'id_producto', pv.id_producto,
              'producto', COALESCE(oi.nombre_producto, p.nombre),
              'imagen', COALESCE(pv.imagenes->>0, ''),
              'atributos', COALESCE(pv.atributos, '{}'::jsonb),
              'marca', m.nombre,
              'categoria', c.nombre
            )
            ORDER BY oi.id_variante
          ) FILTER (WHERE oi.id_variante IS NOT NULL),
          '[]'::jsonb
        ) AS items
      FROM core.orders o
      LEFT JOIN core.users u
        ON u.id_usuario = o.id_usuario
      LEFT JOIN core.order_items oi
        ON oi.id_orden = o.id_orden
      LEFT JOIN core.product_variants pv
        ON pv.id_variante = oi.id_variante
      LEFT JOIN core.products p
        ON p.id_producto = pv.id_producto
      LEFT JOIN core.categories c
        ON c.id_categoria = p.id_categoria
      LEFT JOIN core.marcas m
        ON m.id_marca = p.id_marca
      LEFT JOIN core.shipments s
        ON s.id_orden = o.id_orden
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(
          jsonb_build_object(
            'estado', se.estado,
            'titulo', se.titulo,
            'descripcion', se.descripcion,
            'ubicacion', se.ubicacion,
            'fecha_evento', se.fecha_evento
          )
          ORDER BY se.fecha_evento ASC
        ) AS eventos
        FROM core.shipment_events se
        WHERE se.id_envio = s.id_envio
      ) ev ON true
      LEFT JOIN core.direcciones d
        ON d.id_direccion = o.id_direccion_envio
      WHERE LOWER(TRIM(o.estado)) <> 'pendiente_pago'
      GROUP BY
        o.id_orden,
        s.id_envio,
        ev.eventos,
        d.id_direccion,
        u.nombre,
        u."aPaterno",
        u."aMaterno",
        u.email
      ORDER BY o.fecha_creacion DESC;
    `);
  }

  async getUserOrders(id_usuario: number): Promise<any[]> {
    if (!Number.isInteger(id_usuario) || id_usuario <= 0) {
      throw new BadRequestException('El usuario debe ser válido');
    }

    return await this.readerDataSource.query(
      `
      SELECT
        o.id_orden,
        o.id_usuario,
        o.id_direccion_envio,
        o.estado,
        o.subtotal,
        o.descuento,
        o.total,
        o.metodo_pago,
        o.fecha_pago,
        o.fecha_envio,
        o.fecha_entrega,
        o.fecha_creacion,
        s.id_envio,
        s.estado AS estado_envio,
        s.numero_guia AS tracking_number,
        s.paqueteria,
        s.costo_envio,
        s.fecha_entrega_estimada,
        s.fecha_entrega AS fecha_entrega_real,
        s.codigo_confirmacion_generado_en,
        s.entrega_confirmada_por_usuario,
        s.entrega_confirmada_en,
        s.entrega_validada_por_empleado,
        s.entrega_validada_en,
        COALESCE(ev.eventos, '[]'::jsonb) AS eventos_envio,
        jsonb_build_object(
          'calle', d.calle,
          'numero', d.numero,
          'colonia', d.colonia,
          'ciudad', d.ciudad,
          'estado', d.estado,
          'codigo_postal', d.codigo_postal,
          'pais', d.pais
        ) AS direccion_envio,
        COALESCE(SUM(oi.cantidad), 0)::int AS total_productos,
        COALESCE(COUNT(oi.id_variante), 0)::int AS total_items,
        COALESCE(
          jsonb_agg(
            jsonb_build_object(
              'id_variante', oi.id_variante,
              'sku', COALESCE(oi.sku, pv.sku),
              'cantidad', oi.cantidad,
              'precio_unitario', oi.precio_unitario,
              'total', oi.total,
              'id_producto', pv.id_producto,
              'producto', COALESCE(oi.nombre_producto, p.nombre),
              'imagen', COALESCE(pv.imagenes->>0, ''),
              'atributos', COALESCE(pv.atributos, '{}'::jsonb),
              'marca', m.nombre,
              'categoria', c.nombre
            )
            ORDER BY oi.id_variante
          ) FILTER (WHERE oi.id_variante IS NOT NULL),
          '[]'::jsonb
        ) AS items
      FROM core.orders o
      LEFT JOIN core.order_items oi
        ON oi.id_orden = o.id_orden
      LEFT JOIN core.product_variants pv
        ON pv.id_variante = oi.id_variante
      LEFT JOIN core.products p
        ON p.id_producto = pv.id_producto
      LEFT JOIN core.categories c
        ON c.id_categoria = p.id_categoria
      LEFT JOIN core.marcas m
        ON m.id_marca = p.id_marca
      LEFT JOIN core.shipments s
        ON s.id_orden = o.id_orden
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(
          jsonb_build_object(
            'estado', se.estado,
            'titulo', se.titulo,
            'descripcion', se.descripcion,
            'ubicacion', se.ubicacion,
            'fecha_evento', se.fecha_evento
          )
          ORDER BY se.fecha_evento ASC
        ) AS eventos
        FROM core.shipment_events se
        WHERE se.id_envio = s.id_envio
      ) ev ON true
      LEFT JOIN core.direcciones d
        ON d.id_direccion = o.id_direccion_envio
      WHERE o.id_usuario = $1
        AND LOWER(TRIM(o.estado)) <> 'pendiente_pago'
      GROUP BY o.id_orden, s.id_envio, ev.eventos, d.id_direccion
      ORDER BY o.fecha_creacion DESC;
      `,
      [id_usuario],
    );
  }

  async getOrderTracking(id_usuario: number, id_orden: number): Promise<any> {
    this.validatePositiveInteger(id_usuario, 'El usuario debe ser válido');
    this.validatePositiveInteger(id_orden, 'El pedido debe ser válido');

    const rows = await this.readerDataSource.query(
      `
      SELECT o.id_orden
      FROM core.orders o
      WHERE o.id_orden = $1
        AND o.id_usuario = $2
      LIMIT 1;
      `,
      [id_orden, id_usuario],
    );

    if (!rows[0]) {
      throw new BadRequestException('El pedido no existe');
    }

    const tracking = await this.getOrderTrackingForStaff(id_orden);
    delete tracking.codigo_confirmacion_entrega;
    return tracking;
  }

  async getOrderTrackingForStaff(id_orden: number): Promise<any> {
    this.validatePositiveInteger(id_orden, 'El pedido debe ser válido');

    const rows = await this.readerDataSource.query(
      `
      SELECT
        o.id_orden,
        o.estado AS estado_pedido,
        o.total,
        o.fecha_creacion,
        o.fecha_envio,
        o.fecha_entrega,
        s.id_envio,
        s.estado AS estado_envio,
        s.numero_guia AS tracking_number,
        s.paqueteria,
        s.costo_envio,
        s.fecha_entrega_estimada,
        s.fecha_entrega AS fecha_entrega_real,
        s.codigo_confirmacion_entrega,
        s.codigo_confirmacion_generado_en,
        s.entrega_confirmada_por_usuario,
        s.entrega_confirmada_en,
        s.entrega_validada_por_empleado,
        s.entrega_validada_en,
        sm.nombre AS metodo_envio,
        sm.descripcion AS descripcion_envio,
        jsonb_build_object(
          'calle', d.calle,
          'numero', d.numero,
          'colonia', d.colonia,
          'ciudad', d.ciudad,
          'estado', d.estado,
          'codigo_postal', d.codigo_postal,
          'pais', d.pais
        ) AS direccion_envio,
        COALESCE(ev.eventos, '[]'::jsonb) AS eventos_envio
      FROM core.orders o
      LEFT JOIN core.shipments s
        ON s.id_orden = o.id_orden
      LEFT JOIN core.shipping_methods sm
        ON sm.id_metodo_envio = s.id_metodo_envio
      LEFT JOIN core.direcciones d
        ON d.id_direccion = o.id_direccion_envio
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(
          jsonb_build_object(
            'estado', se.estado,
            'titulo', se.titulo,
            'descripcion', se.descripcion,
            'ubicacion', se.ubicacion,
            'fecha_evento', se.fecha_evento
          )
          ORDER BY se.fecha_evento ASC
        ) AS eventos
        FROM core.shipment_events se
        WHERE se.id_envio = s.id_envio
      ) ev ON true
      WHERE o.id_orden = $1
      LIMIT 1;
      `,
      [id_orden],
    );

    if (!rows[0]) {
      throw new BadRequestException('El pedido no existe');
    }

    return rows[0];
  }

  async updateShipment(
    id_orden: number,
    dto: UpdateShipmentDto,
    cambiado_por: number,
  ): Promise<any> {
    this.validatePositiveInteger(id_orden, 'El pedido debe ser válido');
    this.validatePositiveInteger(cambiado_por, 'El usuario debe ser válido');

    const shipmentStatus = this.normalizeShipmentStatus(dto.estado);
    const orderStatus = this.mapShipmentStatusToOrderStatus(shipmentStatus);
    const queryRunner = this.editorDataSource.createQueryRunner();

    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const source = queryRunner.manager;
      const orderRows = await source.query(
        `
        SELECT id_orden, id_usuario, estado, fecha_envio, fecha_entrega
        FROM core.orders
        WHERE id_orden = $1
        FOR UPDATE;
        `,
        [id_orden],
      );
      const order = orderRows[0];

      if (!order) {
        throw new BadRequestException('El pedido no existe');
      }

      if (String(order.estado || '').trim().toLowerCase() === 'entregado') {
        throw new BadRequestException(
          'Los pedidos entregados ya están finalizados y no se pueden modificar',
        );
      }

      if (String(order.estado || '').trim().toLowerCase() === 'pendiente_pago') {
        throw new BadRequestException(
          'El pedido aún no tiene el pago confirmado',
        );
      }

      let shipmentRows = await source.query(
        `
        SELECT
          id_envio,
          estado,
          numero_guia,
          paqueteria,
          codigo_confirmacion_entrega,
          entrega_confirmada_por_usuario,
          entrega_validada_por_empleado
        FROM core.shipments
        WHERE id_orden = $1
        FOR UPDATE;
        `,
        [id_orden],
      );

      if (shipmentRows.length === 0) {
        shipmentRows = await source.query(
          `
          INSERT INTO core.shipments (
            id_orden,
            estado,
            costo_envio,
            creado_por,
            actualizado_por,
            fecha_creacion,
            fecha_actualizacion
          )
          VALUES ($1, 'pendiente', 0, $2, $2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
          RETURNING id_envio;
          `,
          [id_orden, cambiado_por],
        );
        shipmentRows[0] = {
          ...shipmentRows[0],
          estado: 'pendiente',
          numero_guia: null,
          paqueteria: null,
          codigo_confirmacion_entrega: null,
          entrega_confirmada_por_usuario: false,
          entrega_validada_por_empleado: false,
        };
      }

      const idEnvio = Number(shipmentRows[0].id_envio);
      const currentShipmentStatus = this.normalizeShipmentStatus(
        shipmentRows[0].estado || 'pendiente',
      );
      const trackingNumber = this.cleanOptionalText(dto.tracking_number, 80);
      const carrier = this.cleanOptionalText(dto.paqueteria, 80);
      const location = this.cleanOptionalText(dto.ubicacion, 120);
      const comment = this.cleanOptionalText(dto.comentario, 255);
      const effectiveTracking = trackingNumber || shipmentRows[0].numero_guia;
      const effectiveCarrier = carrier || shipmentRows[0].paqueteria;

      this.validateShipmentTransition(
        currentShipmentStatus,
        shipmentStatus,
        Boolean(shipmentRows[0].entrega_confirmada_por_usuario),
        Boolean(shipmentRows[0].codigo_confirmacion_entrega),
      );

      if (shipmentStatus === 'enviado' && (!effectiveTracking || !effectiveCarrier)) {
        throw new BadRequestException(
          'Para enviar el pedido debes registrar número de guía y paquetería',
        );
      }

      await source.query(
        `
        UPDATE core.shipments
        SET estado = $2::varchar,
            numero_guia = COALESCE($3, numero_guia),
            paqueteria = COALESCE($4, paqueteria),
            fecha_entrega_estimada = COALESCE($5::timestamp, fecha_entrega_estimada),
            fecha_envio = CASE
              WHEN $2::varchar IN ('enviado', 'en_transito', 'entregado') AND fecha_envio IS NULL
                THEN CURRENT_TIMESTAMP
              ELSE fecha_envio
            END,
            fecha_entrega = CASE
              WHEN $2::varchar = 'entregado' THEN CURRENT_TIMESTAMP
              ELSE fecha_entrega
            END,
            entrega_validada_por_empleado = CASE
              WHEN $2::varchar = 'entregado' THEN true
              ELSE entrega_validada_por_empleado
            END,
            entrega_validada_en = CASE
              WHEN $2::varchar = 'entregado' THEN CURRENT_TIMESTAMP
              ELSE entrega_validada_en
            END,
            entrega_validada_por = CASE
              WHEN $2::varchar = 'entregado' THEN $6
              ELSE entrega_validada_por
            END,
            actualizado_por = $6,
            fecha_actualizacion = CURRENT_TIMESTAMP
        WHERE id_envio = $1;
        `,
        [
          idEnvio,
          shipmentStatus,
          trackingNumber,
          carrier,
          dto.fecha_entrega_estimada || null,
          cambiado_por,
        ],
      );

      await source.query(
        `
        INSERT INTO core.shipment_events (
          id_envio,
          estado,
          titulo,
          descripcion,
          ubicacion,
          registrado_por
        )
        VALUES ($1, $2, $3, $4, $5, $6);
        `,
        [
          idEnvio,
          shipmentStatus,
          this.getShipmentEventTitle(shipmentStatus),
          comment || this.getShipmentEventDescription(shipmentStatus),
          location,
          cambiado_por,
        ],
      );

      const previousOrderStatus = String(order.estado || '').trim().toLowerCase();
      const updates: string[] = ['estado = $2'];
      const params: any[] = [id_orden, orderStatus];

      if (orderStatus === 'en proceso' && !order.fecha_envio) {
        updates.push(`fecha_envio = CURRENT_TIMESTAMP`);
      }

      if (orderStatus === 'entregado') {
        updates.push(`fecha_entrega = CURRENT_TIMESTAMP`);
      }

      await source.query(
        `
        UPDATE core.orders
        SET ${updates.join(', ')}
        WHERE id_orden = $1;
        `,
        params,
      );

      if (previousOrderStatus !== orderStatus) {
        await source.query(
          `
          INSERT INTO core.order_status_history (
            id_orden,
            estado_anterior,
            estado_nuevo,
            comentario,
            cambiado_por
          )
          VALUES ($1, $2, $3, $4, $5);
          `,
          [
            id_orden,
            previousOrderStatus || null,
            orderStatus,
            comment || this.getShipmentEventDescription(shipmentStatus),
            cambiado_por,
          ],
        );
      }

      await queryRunner.commitTransaction();
      const tracking = await this.getOrderTrackingForStaff(id_orden);
      this.notifyShipmentStatus(id_orden, shipmentStatus).catch((error) =>
        this.logger.error('Error al enviar correo de estado de pedido:', error),
      );

      return {
        message: 'Envío actualizado correctamente',
        tracking,
      };
    } catch (error) {
      await queryRunner.rollbackTransaction();

      if (error instanceof BadRequestException) {
        throw error;
      }

      this.logger.error('Error al actualizar envío:', error);
      throw new BadRequestException('No fue posible actualizar el envío');
    } finally {
      await queryRunner.release();
    }
  }

  async generateDeliveryConfirmationCode(
    id_orden: number,
    generado_por: number,
  ): Promise<any> {
    this.validatePositiveInteger(id_orden, 'El pedido debe ser válido');
    this.validatePositiveInteger(generado_por, 'El usuario debe ser válido');

    const queryRunner = this.editorDataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const source = queryRunner.manager;
      const rows = await source.query(
        `
        SELECT
          o.id_orden,
          o.estado AS estado_pedido,
          s.id_envio,
          s.estado AS estado_envio,
          s.codigo_confirmacion_entrega,
          s.entrega_confirmada_por_usuario,
          s.entrega_validada_por_empleado
        FROM core.orders o
        LEFT JOIN core.shipments s
          ON s.id_orden = o.id_orden
        WHERE o.id_orden = $1
        FOR UPDATE OF o;
        `,
        [id_orden],
      );

      const order = rows[0];
      if (!order) {
        throw new BadRequestException('El pedido no existe');
      }

      const orderStatus = String(order.estado_pedido || '').trim().toLowerCase();
      if (orderStatus === 'pendiente_pago') {
        throw new BadRequestException('El pedido aún no tiene el pago confirmado');
      }

      if (orderStatus === 'entregado' || order.entrega_validada_por_empleado) {
        throw new BadRequestException('El pedido ya fue finalizado');
      }

      const shipmentStatus = this.normalizeShipmentStatus(order.estado_envio || 'pendiente');
      if (shipmentStatus === 'pendiente') {
        throw new BadRequestException('Primero debes marcar el pedido como preparado');
      }

      if (order.entrega_confirmada_por_usuario) {
        throw new BadRequestException(
          'El cliente ya confirmó este código; no se puede generar otro',
        );
      }

      if (order.codigo_confirmacion_entrega) {
        await queryRunner.commitTransaction();
        const tracking = await this.getOrderTrackingForStaff(id_orden);

        return {
          message: 'Código de confirmación listo para imprimir',
          code: String(order.codigo_confirmacion_entrega).toUpperCase(),
          tracking,
        };
      }

      let idEnvio = Number(order.id_envio || 0);
      if (!idEnvio) {
        const shipmentRows = await source.query(
          `
          INSERT INTO core.shipments (
            id_orden,
            estado,
            costo_envio,
            creado_por,
            actualizado_por,
            fecha_creacion,
            fecha_actualizacion
          )
          VALUES ($1, 'pendiente', 0, $2, $2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
          RETURNING id_envio;
          `,
          [id_orden, generado_por],
        );
        idEnvio = Number(shipmentRows[0].id_envio);
      }

      const code = this.generateDeliveryCode();
      await source.query(
        `
        UPDATE core.shipments
        SET codigo_confirmacion_entrega = $2,
            codigo_confirmacion_generado_en = CURRENT_TIMESTAMP,
            codigo_confirmacion_generado_por = $3,
            entrega_confirmada_por_usuario = false,
            entrega_confirmada_en = NULL,
            entrega_validada_por_empleado = false,
            entrega_validada_en = NULL,
            entrega_validada_por = NULL,
            actualizado_por = $3,
            fecha_actualizacion = CURRENT_TIMESTAMP
        WHERE id_envio = $1;
        `,
        [idEnvio, code, generado_por],
      );

      await source.query(
        `
        INSERT INTO core.shipment_events (
          id_envio,
          estado,
          titulo,
          descripcion,
          registrado_por
        )
        VALUES ($1, 'preparando', 'Código de entrega generado', 'Se generó el código físico de confirmación de entrega.', $2);
        `,
        [idEnvio, generado_por],
      );

      await queryRunner.commitTransaction();
      const tracking = await this.getOrderTrackingForStaff(id_orden);

      return {
        message: 'Código de confirmación generado correctamente',
        code,
        tracking,
      };
    } catch (error) {
      await queryRunner.rollbackTransaction();

      if (error instanceof BadRequestException) {
        throw error;
      }

      this.logger.error('Error al generar código de entrega:', error);
      throw new BadRequestException('No fue posible generar el código');
    } finally {
      await queryRunner.release();
    }
  }

  async confirmDeliveryByCustomer(
    id_usuario: number,
    id_orden: number,
    codigo: string,
  ): Promise<any> {
    this.validatePositiveInteger(id_usuario, 'El usuario debe ser válido');
    this.validatePositiveInteger(id_orden, 'El pedido debe ser válido');

    const cleanCode = String(codigo || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (!/^[A-Z0-9]{10}$/.test(cleanCode)) {
      throw new BadRequestException('El código debe tener 10 caracteres');
    }

    const queryRunner = this.editorDataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const source = queryRunner.manager;
      const rows = await source.query(
        `
        SELECT
          o.id_orden,
          s.id_envio,
          s.estado AS estado_envio,
          s.codigo_confirmacion_entrega,
          s.entrega_confirmada_por_usuario,
          s.entrega_validada_por_empleado
        FROM core.orders o
        INNER JOIN core.shipments s
          ON s.id_orden = o.id_orden
        WHERE o.id_orden = $1
          AND o.id_usuario = $2
        FOR UPDATE OF o, s;
        `,
        [id_orden, id_usuario],
      );

      const order = rows[0];
      if (!order) {
        throw new BadRequestException('El pedido no existe');
      }

      if (order.entrega_validada_por_empleado) {
        throw new BadRequestException('Este pedido ya fue finalizado');
      }

      if (order.entrega_confirmada_por_usuario) {
        throw new BadRequestException('Ya confirmaste la recepción de este pedido');
      }

      if (!order.codigo_confirmacion_entrega) {
        throw new BadRequestException('Este pedido aún no tiene código de entrega');
      }

      if (this.normalizeShipmentStatus(order.estado_envio) !== 'en_transito') {
        throw new BadRequestException(
          'Solo puedes confirmar la recepción cuando el pedido esté en tránsito',
        );
      }

      if (String(order.codigo_confirmacion_entrega).toUpperCase() !== cleanCode) {
        throw new BadRequestException('El código de confirmación no coincide');
      }

      await source.query(
        `
        UPDATE core.shipments
        SET entrega_confirmada_por_usuario = true,
            entrega_confirmada_en = CURRENT_TIMESTAMP,
            actualizado_por = $2,
            fecha_actualizacion = CURRENT_TIMESTAMP
        WHERE id_envio = $1;
        `,
        [order.id_envio, id_usuario],
      );

      await source.query(
        `
        INSERT INTO core.shipment_events (
          id_envio,
          estado,
          titulo,
          descripcion,
          registrado_por
        )
        VALUES ($1, 'en_transito', 'Recepción confirmada por cliente', 'El cliente ingresó correctamente el código incluido en el paquete.', $2);
        `,
        [order.id_envio, id_usuario],
      );

      await queryRunner.commitTransaction();
      const tracking = await this.getOrderTracking(id_usuario, id_orden);

      return {
        message: 'Recepción confirmada. El empleado validará el cierre del pedido.',
        tracking,
      };
    } catch (error) {
      await queryRunner.rollbackTransaction();

      if (error instanceof BadRequestException) {
        throw error;
      }

      this.logger.error('Error al confirmar código de entrega:', error);
      throw new BadRequestException('No fue posible confirmar la entrega');
    } finally {
      await queryRunner.release();
    }
  }

  async createReturnRequest(
    id_usuario: number,
    dto: CreateReturnDto,
  ): Promise<any> {
    this.validatePositiveInteger(id_usuario, 'El usuario debe ser válido');
    this.validatePositiveInteger(dto.id_orden, 'El pedido debe ser válido');

    if (!dto.items?.length) {
      throw new BadRequestException('Selecciona al menos un producto');
    }

    const queryRunner = this.editorDataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const source = queryRunner.manager;
      const orderRows = await source.query(
        `
        SELECT id_orden, estado
        FROM core.orders
        WHERE id_orden = $1
          AND id_usuario = $2
        LIMIT 1;
        `,
        [dto.id_orden, id_usuario],
      );

      const order = orderRows[0];

      if (!order) {
        throw new BadRequestException('El pedido no existe');
      }

      if (String(order.estado || '').trim().toLowerCase() !== 'entregado') {
        throw new BadRequestException(
          'Solo puedes solicitar devolución de pedidos entregados',
        );
      }

      const existingRows = await source.query(
        `
        SELECT id_devolucion
        FROM core.returns
        WHERE id_orden = $1
          AND id_usuario = $2
          AND estado IN ('solicitada', 'aprobada', 'recibida')
        LIMIT 1;
        `,
        [dto.id_orden, id_usuario],
      );

      if (existingRows[0]) {
        throw new BadRequestException(
          'Ya existe una devolución activa para este pedido',
        );
      }

      const orderItems = await source.query(
        `
        SELECT id_variante, cantidad, precio_unitario
        FROM core.order_items
        WHERE id_orden = $1;
        `,
        [dto.id_orden],
      );
      const available = new Map<number, { cantidad: number; precio_unitario: number }>(
        orderItems.map((item) => [
          Number(item.id_variante),
          {
            cantidad: Number(item.cantidad),
            precio_unitario: Number(item.precio_unitario || 0),
          },
        ]),
      );

      for (const item of dto.items) {
        const purchased = available.get(Number(item.id_variante));
        const purchasedQuantity = purchased?.cantidad || 0;

        if (purchasedQuantity <= 0) {
          throw new BadRequestException(
            'Uno de los productos no pertenece a este pedido',
          );
        }

        if (Number(item.cantidad) > purchasedQuantity) {
          throw new BadRequestException(
            'La cantidad a devolver supera lo comprado',
          );
        }
      }

      const rows = await source.query(
        `
        INSERT INTO core.returns (
          id_orden,
          id_usuario,
          estado,
          motivo,
          descripcion,
          solicitado_en,
          fecha_actualizacion
        )
        VALUES ($1, $2, 'solicitada', $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING id_devolucion;
        `,
        [
          dto.id_orden,
          id_usuario,
          this.cleanRequiredText(dto.motivo, 120),
          this.cleanOptionalText(dto.comentario, 500),
        ],
      );

      const idDevolucion = Number(rows[0].id_devolucion);

      for (const item of dto.items) {
        const purchased = available.get(Number(item.id_variante));
        const unitPrice = Number(purchased?.precio_unitario || 0);
        const quantity = Number(item.cantidad);

        await source.query(
          `
          INSERT INTO core.return_items (
            id_devolucion,
            id_orden,
            id_variante,
            cantidad,
            precio_unitario,
            total,
            motivo,
            aprobado
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, false);
          `,
          [
            idDevolucion,
            dto.id_orden,
            Number(item.id_variante),
            quantity,
            unitPrice,
            this.roundMoney(unitPrice * quantity),
            this.cleanOptionalText(item.motivo, 180),
          ],
        );
      }

      await source.query(
        `
        INSERT INTO core.return_events (
          id_devolucion,
          estado,
          comentario,
          registrado_por
        )
        VALUES (
          $1,
          'solicitada',
          'El cliente solicitó la devolución.',
          $2
        );
        `,
        [idDevolucion, id_usuario],
      );

      await queryRunner.commitTransaction();

      return {
        message: 'Solicitud de devolución registrada correctamente',
        return: await this.getReturnById(idDevolucion),
      };
    } catch (error) {
      await queryRunner.rollbackTransaction();

      if (error instanceof BadRequestException) {
        throw error;
      }

      this.logger.error('Error al solicitar devolución:', error);
      throw new BadRequestException('No fue posible solicitar la devolución');
    } finally {
      await queryRunner.release();
    }
  }

  async getUserReturns(id_usuario: number): Promise<any[]> {
    this.validatePositiveInteger(id_usuario, 'El usuario debe ser válido');
    return this.getReturns({ id_usuario });
  }

  async getAllReturns(): Promise<any[]> {
    return this.getReturns({});
  }

  async updateReturnStatus(
    id_devolucion: number,
    dto: UpdateReturnStatusDto,
    cambiado_por: number,
  ): Promise<any> {
    this.validatePositiveInteger(id_devolucion, 'La devolución debe ser válida');
    this.validatePositiveInteger(cambiado_por, 'El usuario debe ser válido');

    const normalizedStatus = String(dto.estado || '').trim().toLowerCase();
    const allowed = [
      'solicitada',
      'aprobada',
      'rechazada',
      'recibida',
      'reembolsada',
      'cerrada',
    ];

    if (!allowed.includes(normalizedStatus)) {
      throw new BadRequestException('El estado de devolución no es válido');
    }

    const queryRunner = this.editorDataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const source = queryRunner.manager;
      const rows = await source.query(
        `
        SELECT id_devolucion, estado
        FROM core.returns
        WHERE id_devolucion = $1
        FOR UPDATE;
        `,
        [id_devolucion],
      );

      const returnRequest = rows[0];

      if (!returnRequest) {
        throw new BadRequestException('La devolución no existe');
      }

      await source.query(
        `
        UPDATE core.returns
        SET estado = $2::varchar,
            resolucion = COALESCE($3, resolucion),
            resuelto_por = CASE
              WHEN $2::varchar IN ('aprobada', 'rechazada', 'reembolsada', 'cerrada') THEN $4
              ELSE resuelto_por
            END,
            resuelto_en = CASE
              WHEN $2::varchar IN ('aprobada', 'rechazada', 'reembolsada', 'cerrada') THEN CURRENT_TIMESTAMP
              ELSE resuelto_en
            END,
            fecha_actualizacion = CURRENT_TIMESTAMP
        WHERE id_devolucion = $1;
        `,
        [
          id_devolucion,
          normalizedStatus,
          this.cleanOptionalText(dto.comentario, 500),
          cambiado_por,
        ],
      );

      await source.query(
        `
        INSERT INTO core.return_events (
          id_devolucion,
          estado,
          comentario,
          registrado_por
        )
        VALUES ($1, $2, $3, $4);
        `,
        [
          id_devolucion,
          normalizedStatus,
          this.cleanOptionalText(dto.comentario, 500) ||
            this.getReturnEventDescription(normalizedStatus),
          cambiado_por,
        ],
      );

      await queryRunner.commitTransaction();

      return {
        message: 'Devolución actualizada correctamente',
        return: await this.getReturnById(id_devolucion),
      };
    } catch (error) {
      await queryRunner.rollbackTransaction();

      if (error instanceof BadRequestException) {
        throw error;
      }

      this.logger.error('Error al actualizar devolución:', error);
      throw new BadRequestException('No fue posible actualizar la devolución');
    } finally {
      await queryRunner.release();
    }
  }

  async updateOrderStatus(
    id_orden: number,
    estado: string,
    cambiado_por = 1,
  ): Promise<{ message: string; order: Orders }> {
    if (!Number.isInteger(id_orden) || id_orden <= 0) {
      throw new BadRequestException('El pedido debe ser válido');
    }

    const normalizedStatus = String(estado || '').trim().toLowerCase();
    const allowedStatuses = ['pendiente', 'en proceso', 'entregado'];

    if (!allowedStatuses.includes(normalizedStatus)) {
      throw new BadRequestException(
        'El estado debe ser pendiente, en proceso o entregado',
      );
    }

    const shipmentStatus =
      normalizedStatus === 'entregado'
        ? 'entregado'
        : normalizedStatus === 'en proceso'
          ? 'preparando'
          : 'pendiente';

    await this.updateShipment(
      id_orden,
      {
        estado: shipmentStatus,
        comentario: `Estado del pedido actualizado a ${normalizedStatus}`,
      } as UpdateShipmentDto,
      cambiado_por,
    );

    const savedOrder = await this.ordersReaderRepository.findOne({
      where: { id_orden },
    });

    return {
      message: 'Estado del pedido actualizado correctamente',
      order: savedOrder as Orders,
    };
  }

  private validatePositiveInteger(value: number, message: string): void {
    if (!Number.isInteger(Number(value)) || Number(value) <= 0) {
      throw new BadRequestException(message);
    }
  }

  private generateDeliveryCode(): string {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = randomBytes(10);
    return Array.from(bytes)
      .map((byte) => alphabet[byte % alphabet.length])
      .join('');
  }

  private validateShipmentTransition(
    currentStatus: string,
    nextStatus: string,
    deliveryConfirmedByCustomer: boolean,
    deliveryCodeGenerated: boolean,
  ): void {
    if (currentStatus === 'entregado') {
      throw new BadRequestException('El pedido ya fue entregado y no se puede modificar');
    }

    if (currentStatus === nextStatus) {
      throw new BadRequestException('Este estado ya fue registrado');
    }

    const nextByCurrent: Record<string, string> = {
      pendiente: 'preparando',
      preparando: 'enviado',
      enviado: 'en_transito',
      en_transito: 'entregado',
    };

    const expectedNext = nextByCurrent[currentStatus];
    if (nextStatus !== expectedNext) {
      throw new BadRequestException(
        `El flujo correcto es pendiente -> preparando -> enviado -> en_transito -> entregado. El siguiente estado válido es ${expectedNext || 'ninguno'}.`,
      );
    }

    if (nextStatus === 'enviado' && !deliveryCodeGenerated) {
      throw new BadRequestException(
        'Antes de enviar el pedido debes generar e imprimir el código de confirmación de entrega',
      );
    }

    if (nextStatus === 'entregado' && !deliveryConfirmedByCustomer) {
      throw new BadRequestException(
        'El cliente debe confirmar la recepción con el código antes de finalizar el pedido',
      );
    }
  }

  private async notifyShipmentStatus(id_orden: number, status: string): Promise<void> {
    const summary = await this.getOrderEmailSummary(id_orden);
    if (!summary?.email) return;

    if (status === 'entregado') {
      await this.mailService.sendOrderDeliveredEmail(
        summary.email,
        summary.cliente,
        summary,
      );
      return;
    }

    await this.mailService.sendOrderStatusEmail(
      summary.email,
      summary.cliente,
      summary,
      this.getShipmentStatusLabelForEmail(status),
      this.getShipmentEventDescription(status),
    );
  }

  private async getOrderEmailSummary(id_orden: number): Promise<any> {
    const rows = await this.readerDataSource.query(
      `
      SELECT
        o.id_orden,
        o.total,
        o.estado,
        o.fecha_creacion,
        s.estado AS estado_envio,
        s.numero_guia AS tracking_number,
        s.paqueteria,
        COALESCE(
          NULLIF(TRIM(CONCAT_WS(' ', u.nombre, u."aPaterno", u."aMaterno")), ''),
          'Cliente'
        ) AS cliente,
        u.email,
        COALESCE(items.items, '[]'::jsonb) AS items
      FROM core.orders o
      INNER JOIN core.users u
        ON u.id_usuario = o.id_usuario
      LEFT JOIN core.shipments s
        ON s.id_orden = o.id_orden
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(
          jsonb_build_object(
            'producto', COALESCE(oi.nombre_producto, p.nombre),
            'cantidad', oi.cantidad,
            'total', oi.total
          )
          ORDER BY oi.id_variante
        ) AS items
        FROM core.order_items oi
        LEFT JOIN core.product_variants pv
          ON pv.id_variante = oi.id_variante
        LEFT JOIN core.products p
          ON p.id_producto = pv.id_producto
        WHERE oi.id_orden = o.id_orden
      ) items ON true
      WHERE o.id_orden = $1
      LIMIT 1;
      `,
      [id_orden],
    );

    return rows[0] || null;
  }

  private getShipmentStatusLabelForEmail(status: string): string {
    const labels: Record<string, string> = {
      pendiente: 'Pedido pendiente',
      preparando: 'Pedido en preparación',
      enviado: 'Pedido enviado',
      en_transito: 'Pedido en tránsito',
      entregado: 'Pedido entregado',
      incidencia: 'Incidencia en envío',
    };

    return labels[String(status || '').replace(/\s+/g, '_')] || 'Actualización de pedido';
  }

  private normalizeShipmentStatus(status: string): string {
    const normalized = String(status || '').trim().toLowerCase().replace(/\s+/g, '_');
    const allowed = [
      'pendiente',
      'preparando',
      'enviado',
      'en_transito',
      'entregado',
      'incidencia',
    ];

    if (!allowed.includes(normalized)) {
      throw new BadRequestException('El estado de envío no es válido');
    }

    return normalized;
  }

  private mapShipmentStatusToOrderStatus(status: string): string {
    if (status === 'entregado') {
      return 'entregado';
    }

    if (['preparando', 'enviado', 'en_transito', 'incidencia'].includes(status)) {
      return 'en proceso';
    }

    return 'pendiente';
  }

  private cleanOptionalText(value: string | undefined, maxLength: number): string | null {
    const cleaned = String(value || '')
      .trim()
      .replace(/[<>`{}\[\]\\|]/g, '')
      .replace(/\s+/g, ' ')
      .slice(0, maxLength);

    return cleaned || null;
  }

  private cleanRequiredText(value: string, maxLength: number): string {
    const cleaned = this.cleanOptionalText(value, maxLength);

    if (!cleaned) {
      throw new BadRequestException('El texto es obligatorio');
    }

    return cleaned;
  }

  private roundMoney(value: number): number {
    return Math.round((Number(value) || 0) * 100) / 100;
  }

  private getShipmentEventTitle(status: string): string {
    const titles: Record<string, string> = {
      pendiente: 'Pedido pendiente',
      preparando: 'Pedido en preparación',
      enviado: 'Pedido enviado',
      en_transito: 'Pedido en tránsito',
      entregado: 'Pedido entregado',
      incidencia: 'Incidencia en envío',
    };

    return titles[String(status || '').replace(/\s+/g, '_')] || 'Actualización de envío';
  }

  private getShipmentEventDescription(status: string): string {
    const descriptions: Record<string, string> = {
      pendiente: 'El pedido está pendiente de preparación.',
      preparando: 'El pedido se está preparando para envío.',
      enviado: 'El pedido fue entregado a la paquetería.',
      en_transito: 'El pedido está en camino.',
      entregado: 'El pedido fue marcado como entregado.',
      incidencia: 'Se registró una incidencia en el envío.',
    };

    return descriptions[String(status || '').replace(/\s+/g, '_')] || 'Se registró una actualización del envío.';
  }

  private getReturnEventTitle(status: string): string {
    const titles: Record<string, string> = {
      solicitada: 'Solicitud registrada',
      aprobada: 'Devolución aprobada',
      rechazada: 'Devolución rechazada',
      recibida: 'Producto recibido',
      reembolsada: 'Reembolso registrado',
      cerrada: 'Devolución cerrada',
    };

    return titles[status] || 'Actualización de devolución';
  }

  private getReturnEventDescription(status: string): string {
    const descriptions: Record<string, string> = {
      solicitada: 'La devolución fue solicitada por el cliente.',
      aprobada: 'La devolución fue aprobada.',
      rechazada: 'La devolución fue rechazada.',
      recibida: 'El producto devuelto fue recibido.',
      reembolsada: 'El reembolso fue registrado.',
      cerrada: 'La devolución fue cerrada.',
    };

    return descriptions[status] || 'Se registró una actualización de devolución.';
  }

  private async getReturnById(id_devolucion: number): Promise<any> {
    const rows = await this.getReturns({ id_devolucion });
    return rows[0] || null;
  }

  private async getReturns(filters: {
    id_usuario?: number;
    id_devolucion?: number;
  }): Promise<any[]> {
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.id_usuario) {
      params.push(filters.id_usuario);
      conditions.push(`r.id_usuario = $${params.length}`);
    }

    if (filters.id_devolucion) {
      params.push(filters.id_devolucion);
      conditions.push(`r.id_devolucion = $${params.length}`);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    return this.readerDataSource.query(
      `
      SELECT
        r.id_devolucion,
        r.id_orden,
        r.id_usuario,
        r.estado,
        r.motivo,
        r.descripcion AS comentario,
        r.resolucion,
        r.solicitado_en AS fecha_solicitud,
        r.fecha_actualizacion,
        r.resuelto_en AS fecha_resolucion,
        COALESCE(
          NULLIF(TRIM(CONCAT_WS(' ', u.nombre, u."aPaterno", u."aMaterno")), ''),
          'Usuario'
        ) AS cliente,
        u.email,
        o.total AS total_pedido,
        COALESCE(items.items, '[]'::jsonb) AS items,
        COALESCE(events.eventos, '[]'::jsonb) AS eventos
      FROM core.returns r
      INNER JOIN core.orders o
        ON o.id_orden = r.id_orden
      LEFT JOIN core.users u
        ON u.id_usuario = r.id_usuario
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(
          jsonb_build_object(
            'id_variante', ri.id_variante,
            'cantidad', ri.cantidad,
            'motivo', ri.motivo,
            'sku', COALESCE(oi.sku, pv.sku),
            'producto', COALESCE(oi.nombre_producto, p.nombre),
            'imagen', COALESCE(pv.imagenes->>0, '')
          )
          ORDER BY ri.id_variante
        ) AS items
        FROM core.return_items ri
        LEFT JOIN core.order_items oi
          ON oi.id_orden = r.id_orden
          AND oi.id_variante = ri.id_variante
        LEFT JOIN core.product_variants pv
          ON pv.id_variante = ri.id_variante
        LEFT JOIN core.products p
          ON p.id_producto = pv.id_producto
        WHERE ri.id_devolucion = r.id_devolucion
      ) items ON true
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(
          jsonb_build_object(
            'estado', re.estado,
            'titulo', CASE
              WHEN re.estado = 'solicitada' THEN 'Solicitud registrada'
              WHEN re.estado = 'aprobada' THEN 'Devolución aprobada'
              WHEN re.estado = 'rechazada' THEN 'Devolución rechazada'
              WHEN re.estado = 'recibida' THEN 'Producto recibido'
              WHEN re.estado = 'reembolsada' THEN 'Reembolso registrado'
              WHEN re.estado = 'cerrada' THEN 'Devolución cerrada'
              ELSE 'Actualización de devolución'
            END,
            'descripcion', re.comentario,
            'fecha_evento', re.fecha_evento
          )
          ORDER BY re.fecha_evento ASC
        ) AS eventos
        FROM core.return_events re
        WHERE re.id_devolucion = r.id_devolucion
      ) events ON true
      ${where}
      ORDER BY r.fecha_actualizacion DESC, r.solicitado_en DESC;
      `,
      params,
    );
  }
}
