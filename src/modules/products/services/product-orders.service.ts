/* eslint-disable */
import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';

import { UpdateShipmentDto } from '../dto/orders/update-shipment.dto';
import {
  CreateReturnDto,
  UpdateReturnStatusDto,
} from '../dto/returns/create-return.dto';
import { Orders } from '../entities/orders/orders.entity';

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

    return this.getOrderTrackingForStaff(id_orden);
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
        SELECT id_orden, estado, fecha_envio, fecha_entrega
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
        SELECT id_envio
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
      }

      const idEnvio = Number(shipmentRows[0].id_envio);
      const trackingNumber = this.cleanOptionalText(dto.tracking_number, 80);
      const carrier = this.cleanOptionalText(dto.paqueteria, 80);
      const location = this.cleanOptionalText(dto.ubicacion, 120);
      const comment = this.cleanOptionalText(dto.comentario, 255);

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
