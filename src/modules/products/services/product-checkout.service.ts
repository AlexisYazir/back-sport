/* eslint-disable */
import {
  BadRequestException,
  Injectable,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import axios from 'axios';
import { createHash, randomUUID } from 'crypto';
import { DataSource } from 'typeorm';

import {
  CheckoutAddressDto,
  CheckoutCardDto,
  CreateCheckoutOrderDto,
} from '../dto/checkout/create-checkout-order.dto';

type Queryable = {
  query: (query: string, parameters?: any[]) => Promise<any[]>;
};

type CartItemCartColumn = 'id_carrito' | 'id_carrto';

interface CheckoutTotals {
  subtotal: number;
  discount: number;
  shipping: number;
  total: number;
  itemCount: number;
  freeShippingRemaining: number;
}

interface PromotionResult {
  id_promocion: number;
  nombre: string;
  codigo: string | null;
  tipo: string;
  valor: number;
  descuento: number;
  envioGratis: boolean;
}

interface ResolvedPaymentMethod {
  id_metodo_pago?: number;
  marca: string;
  ultimos4: string;
  referencia: string;
}

interface MercadoPagoPreference {
  id: string;
  init_point?: string;
  sandbox_init_point?: string;
}

@Injectable()
export class ProductCheckoutService {
  private readonly logger = new Logger(ProductCheckoutService.name);
  private cartItemCartColumn?: CartItemCartColumn;

  constructor(
    @InjectDataSource('readerConnection')
    private readonly readerDataSource: DataSource,
    @InjectDataSource('editorConnection')
    private readonly editorDataSource: DataSource,
    private readonly configService: ConfigService,
  ) {}

  async lookupPostalCode(codigoPostal: string): Promise<any> {
    const zipCode = String(codigoPostal || '').trim();

    if (!/^\d{5}$/.test(zipCode)) {
      throw new BadRequestException('El código postal debe tener 5 dígitos');
    }

    const token = this.configService.get<string>('POSTALIA_API_TOKEN');

    if (!token) {
      throw new BadRequestException(
        'No está configurado el token de Postalia en el servidor',
      );
    }

    try {
      const response = await axios.get(
        `https://postalia.com.mx/api/codigos-postales/${zipCode}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
          timeout: 8000,
        },
      );

      return response.data;
    } catch (error) {
      this.logger.error('Error al consultar código postal en Postalia:', error);
      throw new BadRequestException(
        'No fue posible consultar el código postal',
      );
    }
  }

  async getCheckoutSummary(
    id_usuario: number,
    codigo_promocion?: string,
    id_metodo_envio?: number,
  ): Promise<any> {
    this.validateUser(id_usuario);

    const [cart, addresses, shippingMethods, paymentMethods] = await Promise.all([
      this.getActiveCartWithItems(id_usuario, this.readerDataSource, false),
      this.getUserAddresses(id_usuario, this.readerDataSource),
      this.getShippingMethods(this.readerDataSource),
      this.getUserPaymentMethods(id_usuario),
    ]);

    const shippingMethod = this.resolveShippingMethod(
      shippingMethods,
      id_metodo_envio,
    );
    const promotion = await this.calculatePromotion(
      id_usuario,
      cart.items,
      cart.subtotal,
      codigo_promocion,
      this.readerDataSource,
    );
    const totals = this.calculateTotals(
      cart.items,
      shippingMethod,
      promotion,
    );

    return {
      cart: {
        id_carrito: cart.id_carrito,
        items: cart.items,
      },
      addresses,
      shippingMethods,
      paymentMethods,
      selectedShippingMethod: shippingMethod,
      appliedPromotion: promotion,
      totals,
    };
  }

  async confirmCheckout(
    id_usuario: number,
    dto: CreateCheckoutOrderDto,
  ): Promise<any> {
    this.validateUser(id_usuario);

    const queryRunner = this.editorDataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const source = queryRunner.manager;
      const cart = await this.getActiveCartWithItems(id_usuario, source, true);

      if (cart.items.length === 0) {
        throw new BadRequestException('El carrito está vacío');
      }

      this.validateCheckoutItems(cart.items);

      const shippingMethods = await this.getShippingMethods(source);
      const shippingMethod = this.resolveShippingMethod(
        shippingMethods,
        dto.id_metodo_envio,
      );
      const promotion = await this.calculatePromotion(
        id_usuario,
        cart.items,
        cart.subtotal,
        dto.codigo_promocion,
        source,
      );
      const totals = this.calculateTotals(
        cart.items,
        shippingMethod,
        promotion,
      );
      const idDireccion = await this.resolveShippingAddress(
        id_usuario,
        dto,
        source,
      );
      if (dto.metodo_pago !== 'mercado_pago') {
        throw new BadRequestException('El método de pago no es válido');
      }

      const orderRows = await source.query(
        `
        INSERT INTO core.orders (
          id_usuario,
          id_direccion_envio,
          estado,
          subtotal,
          descuento,
          total,
          metodo_pago,
          fecha_pago,
          fecha_creacion
        )
        VALUES (
          $1,
          $2,
          'pendiente_pago',
          $3,
          $4,
          $5,
          $6,
          $7,
          CURRENT_TIMESTAMP
        )
        RETURNING *;
        `,
        [
          id_usuario,
          idDireccion,
          totals.subtotal,
          totals.discount,
          totals.total,
          'mercado_pago',
          null,
        ],
      );

      const order = orderRows[0];
      const idOrden = Number(order.id_orden);

      for (const item of cart.items) {
        await source.query(
          `
          INSERT INTO core.order_items (
            id_orden,
            id_variante,
            nombre_producto,
            sku,
            cantidad,
            precio_unitario,
            total
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7);
          `,
          [
            idOrden,
            item.id_variante,
            item.nombre,
            item.sku,
            item.cantidad,
            item.precio_unitario,
            this.roundMoney(item.precio_unitario * item.cantidad),
          ],
        );
      }

      const externalReference = this.buildMercadoPagoExternalReference(idOrden);
      await this.saveMercadoPagoPayment(
        idOrden,
        totals.total,
        externalReference,
        source,
      );

      const preference = await this.createMercadoPagoPreference({
        idOrden,
        externalReference,
        items: cart.items,
        totals,
        shippingMethod,
        idUsuario: id_usuario,
      });

      await this.saveShipment(
        idOrden,
        id_usuario,
        shippingMethod,
        totals.shipping,
        source,
      );
      await this.saveInitialOrderHistory(idOrden, id_usuario, source);
      await this.savePromotionUsage(
        id_usuario,
        idOrden,
        promotion,
        dto.codigo_promocion,
        source,
      );

      await queryRunner.commitTransaction();

      return {
        message: 'Pedido creado correctamente. Continúa con Mercado Pago.',
        order: {
          ...order,
          subtotal: totals.subtotal,
          descuento: totals.discount,
          total: totals.total,
        },
        totals,
        checkout: {
          provider: 'mercado_pago',
          preference_id: preference.id,
          external_reference: externalReference,
          init_point: preference.init_point,
          sandbox_init_point: preference.sandbox_init_point,
        },
      };
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error('Error al confirmar checkout:', error);

      if (error instanceof BadRequestException) {
        throw error;
      }

      throw new BadRequestException('No fue posible finalizar la compra');
    } finally {
      await queryRunner.release();
    }
  }

  async getUserPaymentMethods(id_usuario: number): Promise<any[]> {
    this.validateUser(id_usuario);

    const rows = await this.readerDataSource.query(
      `
      SELECT
        id_metodo_pago,
        id_usuario,
        alias,
        'tarjeta' AS tipo,
        marca,
        titular,
        ultimos4,
        exp_mes,
        exp_anio,
        principal,
        activo,
        fecha_creacion,
        fecha_actualizacion
      FROM core.user_payment_methods
      WHERE id_usuario = $1
        AND activo = true
      ORDER BY principal DESC, fecha_actualizacion DESC NULLS LAST, fecha_creacion DESC;
      `,
      [id_usuario],
    );

    return rows.map((row) => this.normalizePaymentMethodRow(row));
  }

  async createUserPaymentMethod(
    id_usuario: number,
    dto: CheckoutCardDto,
  ): Promise<any> {
    this.validateUser(id_usuario);
    return this.createPaymentMethodRecord(id_usuario, dto, this.editorDataSource);
  }

  async deleteUserPaymentMethod(
    id_usuario: number,
    id_metodo_pago: number,
  ): Promise<any> {
    this.validateUser(id_usuario);

    if (!Number.isInteger(id_metodo_pago) || id_metodo_pago <= 0) {
      throw new BadRequestException('La tarjeta no es válida');
    }

    const rows = await this.editorDataSource.query(
      `
      UPDATE core.user_payment_methods
      SET activo = false,
          principal = false,
          fecha_actualizacion = CURRENT_TIMESTAMP
      WHERE id_metodo_pago = $1
        AND id_usuario = $2
        AND activo = true
      RETURNING id_metodo_pago;
      `,
      [id_metodo_pago, id_usuario],
    );

    if (rows.length === 0) {
      throw new BadRequestException('La tarjeta no existe o ya fue eliminada');
    }

    return { message: 'Tarjeta eliminada correctamente' };
  }

  async processMercadoPagoWebhook(body: any, query: any): Promise<any> {
    const topic = String(
      body?.type || body?.topic || query?.type || query?.topic || '',
    ).toLowerCase();
    const paymentId =
      body?.data?.id ||
      body?.id ||
      query?.['data.id'] ||
      query?.id;

    if (!paymentId || (topic && !['payment', 'merchant_order'].includes(topic))) {
      return { received: true, ignored: true };
    }

    if (topic === 'merchant_order') {
      return { received: true, ignored: true };
    }

    const payment = await this.getMercadoPagoPayment(String(paymentId));
    await this.syncMercadoPagoPayment(payment);

    return {
      received: true,
      provider: 'mercado_pago',
      paymentId: String(paymentId),
      status: payment?.status || null,
    };
  }

  private validateUser(id_usuario: number): void {
    if (!Number.isInteger(id_usuario) || id_usuario <= 0) {
      throw new BadRequestException('El usuario debe ser válido');
    }
  }

  private async getCartItemCartColumn(
    source: Queryable,
  ): Promise<CartItemCartColumn> {
    if (this.cartItemCartColumn) {
      return this.cartItemCartColumn;
    }

    const rows = await source.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'core'
        AND table_name = 'cart_items'
        AND column_name IN ('id_carrito', 'id_carrto')
      ORDER BY CASE WHEN column_name = 'id_carrito' THEN 0 ELSE 1 END
      LIMIT 1;
    `);

    const column = rows?.[0]?.column_name;
    this.cartItemCartColumn =
      column === 'id_carrto' ? 'id_carrto' : 'id_carrito';

    return this.cartItemCartColumn;
  }

  private async getActiveCartWithItems(
    id_usuario: number,
    source: Queryable,
    lock: boolean,
  ): Promise<any> {
    const cartRows = await source.query(
      `
      SELECT id_carrito, id_usuario, estado, fecha_creacion, fecha_actualizacion
      FROM core.carts
      WHERE id_usuario = $1
        AND LOWER(TRIM(estado)) = 'activo'
      ORDER BY fecha_actualizacion DESC NULLS LAST, fecha_creacion DESC
      LIMIT 1
      ${lock ? 'FOR UPDATE' : ''};
      `,
      [id_usuario],
    );

    const cart = cartRows[0];

    if (!cart) {
      return {
        id_carrito: null,
        items: [],
        subtotal: 0,
      };
    }

    const cartColumn = await this.getCartItemCartColumn(source);
    const items = await source.query(
      `
      SELECT
        ci.${cartColumn} AS id_carrito,
        ci.id_variante,
        ci.cantidad,
        pv.id_producto,
        pv.sku,
        pv.precio AS precio_unitario,
        pv.imagenes,
        pv.atributos,
        p.nombre,
        p.descripcion,
        p.activo,
        p.id_marca,
        p.id_categoria,
        c.nombre AS categoria,
        m.nombre AS marca,
        COALESCE(i.stock_actual, 0)::int AS stock,
        COALESCE(i.costo_promedio, 0) AS costo_promedio
      FROM core.cart_items ci
      INNER JOIN core.product_variants pv
        ON pv.id_variante = ci.id_variante
      INNER JOIN core.products p
        ON p.id_producto = pv.id_producto
      LEFT JOIN core.categories c
        ON c.id_categoria = p.id_categoria
      LEFT JOIN core.marcas m
        ON m.id_marca = p.id_marca
      LEFT JOIN core.inventory i
        ON i.id_variante = pv.id_variante
      WHERE ci.${cartColumn} = $1
      ORDER BY p.nombre ASC, pv.sku ASC
      ${lock ? 'FOR UPDATE OF ci' : ''};
      `,
      [cart.id_carrito],
    );

    const normalizedItems = items.map((item) => ({
      ...item,
      id_carrito: Number(item.id_carrito),
      id_variante: Number(item.id_variante),
      id_producto: Number(item.id_producto),
      id_marca: item.id_marca ? Number(item.id_marca) : null,
      id_categoria: item.id_categoria ? Number(item.id_categoria) : null,
      cantidad: Number(item.cantidad || 0),
      precio_unitario: Number(item.precio_unitario || 0),
      stock: Number(item.stock || 0),
      costo_promedio: Number(item.costo_promedio || 0),
      imagen: Array.isArray(item.imagenes) ? item.imagenes[0] : null,
      atributos:
        item.atributos && typeof item.atributos === 'object'
          ? item.atributos
          : {},
    }));

    return {
      ...cart,
      id_carrito: Number(cart.id_carrito),
      items: normalizedItems,
      subtotal: this.roundMoney(
        normalizedItems.reduce(
          (total, item) => total + item.precio_unitario * item.cantidad,
          0,
        ),
      ),
    };
  }

  private validateCheckoutItems(items: any[]): void {
    for (const item of items) {
      if (item.activo !== true) {
        throw new BadRequestException(
          `El producto "${item.nombre}" ya no está disponible`,
        );
      }

      if (item.stock <= 0) {
        throw new BadRequestException(
          `El producto "${item.nombre}" no tiene stock disponible`,
        );
      }

      if (item.cantidad > item.stock) {
        throw new BadRequestException(
          `Solo hay ${item.stock} unidades disponibles de "${item.nombre}"`,
        );
      }
    }
  }

  private async getUserAddresses(
    id_usuario: number,
    source: Queryable,
  ): Promise<any[]> {
    return await source.query(
      `
      SELECT
        id_direccion,
        id_usuario,
        alias,
        calle,
        numero,
        colonia,
        ciudad,
        estado,
        codigo_postal,
        pais,
        principal,
        fecha_creacion
      FROM core.direcciones
      WHERE id_usuario = $1
      ORDER BY principal DESC, fecha_creacion DESC;
      `,
      [id_usuario],
    );
  }

  private async getShippingMethods(source: Queryable): Promise<any[]> {
    const methods = await source.query(`
      SELECT
        id_metodo_envio,
        nombre,
        descripcion,
        costo_base,
        envio_gratis_desde,
        dias_min,
        dias_max,
        activo
      FROM core.shipping_methods
      WHERE activo = true
      ORDER BY costo_base ASC, id_metodo_envio ASC;
    `);

    return methods.map((method) => ({
      ...method,
      id_metodo_envio: Number(method.id_metodo_envio),
      costo_base: Number(method.costo_base || 0),
      envio_gratis_desde: 200,
      dias_min: Number(method.dias_min || 1),
      dias_max: Number(method.dias_max || 5),
    }));
  }

  private resolveShippingMethod(
    methods: any[],
    id_metodo_envio?: number,
  ): any {
    if (methods.length === 0) {
      return {
        id_metodo_envio: null,
        nombre: 'Envío estándar',
        descripcion: 'Entrega nacional estándar',
        costo_base: 130,
        envio_gratis_desde: 200,
        dias_min: 2,
        dias_max: 5,
      };
    }

    if (!id_metodo_envio) {
      return methods[0];
    }

    const method = methods.find(
      (item) => Number(item.id_metodo_envio) === Number(id_metodo_envio),
    );

    if (!method) {
      throw new BadRequestException('El método de envío no es válido');
    }

    return method;
  }

  private calculateTotals(
    items: any[],
    shippingMethod: any,
    promotion: PromotionResult | null,
  ): CheckoutTotals {
    const subtotal = this.roundMoney(
      items.reduce(
        (total, item) => total + Number(item.precio_unitario) * item.cantidad,
        0,
      ),
    );
    const discount = this.roundMoney(promotion?.descuento || 0);
    const discountedSubtotal = Math.max(0, subtotal - discount);
    const freeShippingThreshold = shippingMethod?.envio_gratis_desde;
    const hasFreeShippingByThreshold =
      freeShippingThreshold !== null &&
      freeShippingThreshold !== undefined &&
      discountedSubtotal >= Number(freeShippingThreshold);
    const shipping =
      subtotal === 0 || promotion?.envioGratis || hasFreeShippingByThreshold
        ? 0
        : Number(shippingMethod?.costo_base || 0);
    const itemCount = items.reduce((total, item) => total + item.cantidad, 0);
    const freeShippingRemaining =
      freeShippingThreshold === null || freeShippingThreshold === undefined
        ? 0
        : Math.max(0, Number(freeShippingThreshold) - discountedSubtotal);

    return {
      subtotal,
      discount,
      shipping: this.roundMoney(shipping),
      total: this.roundMoney(discountedSubtotal + shipping),
      itemCount,
      freeShippingRemaining: this.roundMoney(freeShippingRemaining),
    };
  }

  private async calculatePromotion(
    id_usuario: number,
    items: any[],
    subtotal: number,
    codigo_promocion: string | undefined,
    source: Queryable,
  ): Promise<PromotionResult | null> {
    const code = String(codigo_promocion || '').trim();

    if (!code) {
      return null;
    }

    const rows = await source.query(
      `
      SELECT *
      FROM core.promotions
      WHERE codigo IS NOT NULL
        AND UPPER(TRIM(codigo)) = UPPER(TRIM($1))
        AND activo = true
        AND CURRENT_TIMESTAMP BETWEEN inicia_en AND termina_en
      LIMIT 1;
      `,
      [code],
    );

    const promotion = rows[0];

    if (!promotion) {
      throw new BadRequestException('El cupón no es válido o ya expiró');
    }

    if (subtotal < Number(promotion.compra_minima || 0)) {
      throw new BadRequestException(
        `Este cupón requiere una compra mínima de $${Number(
          promotion.compra_minima,
        ).toFixed(2)}`,
      );
    }

    await this.validatePromotionUsage(id_usuario, promotion, source);

    const eligibleSubtotal = await this.getPromotionEligibleSubtotal(
      promotion.id_promocion,
      items,
      source,
    );

    if (eligibleSubtotal <= 0 && promotion.tipo !== 'envio_gratis') {
      throw new BadRequestException(
        'El cupón no aplica a los productos del carrito',
      );
    }

    let discount = 0;
    const value = Number(promotion.valor || 0);

    if (promotion.tipo === 'porcentaje') {
      discount = eligibleSubtotal * (value / 100);
    } else if (promotion.tipo === 'monto_fijo') {
      discount = Math.min(value, eligibleSubtotal);
    }

    if (promotion.descuento_maximo !== null) {
      discount = Math.min(discount, Number(promotion.descuento_maximo));
    }

    return {
      id_promocion: Number(promotion.id_promocion),
      nombre: promotion.nombre,
      codigo: promotion.codigo,
      tipo: promotion.tipo,
      valor: value,
      descuento: this.roundMoney(discount),
      envioGratis: promotion.tipo === 'envio_gratis',
    };
  }

  private async validatePromotionUsage(
    id_usuario: number,
    promotion: any,
    source: Queryable,
  ): Promise<void> {
    if (promotion.uso_maximo) {
      const totalRows = await source.query(
        `
        SELECT COUNT(*)::int AS total
        FROM core.promotion_redemptions
        WHERE id_promocion = $1;
        `,
        [promotion.id_promocion],
      );

      if (Number(totalRows[0]?.total || 0) >= Number(promotion.uso_maximo)) {
        throw new BadRequestException('El cupón alcanzó su límite de uso');
      }
    }

    if (promotion.uso_por_usuario) {
      const userRows = await source.query(
        `
        SELECT COUNT(*)::int AS total
        FROM core.promotion_redemptions
        WHERE id_promocion = $1
          AND id_usuario = $2;
        `,
        [promotion.id_promocion, id_usuario],
      );

      if (
        Number(userRows[0]?.total || 0) >= Number(promotion.uso_por_usuario)
      ) {
        throw new BadRequestException('Ya usaste este cupón');
      }
    }
  }

  private async getPromotionEligibleSubtotal(
    id_promocion: number,
    items: any[],
    source: Queryable,
  ): Promise<number> {
    const targets = await source.query(
      `
      SELECT tipo_objetivo, id_objetivo
      FROM core.promotion_targets
      WHERE id_promocion = $1;
      `,
      [id_promocion],
    );

    if (targets.length === 0) {
      return this.roundMoney(
        items.reduce(
          (total, item) => total + item.precio_unitario * item.cantidad,
          0,
        ),
      );
    }

    return this.roundMoney(
      items
        .filter((item) =>
          targets.some((target) => {
            const idObjetivo = Number(target.id_objetivo);
            switch (target.tipo_objetivo) {
              case 'producto':
                return item.id_producto === idObjetivo;
              case 'variante':
                return item.id_variante === idObjetivo;
              case 'marca':
                return item.id_marca === idObjetivo;
              case 'categoria':
                return item.id_categoria === idObjetivo;
              default:
                return false;
            }
          }),
        )
        .reduce(
          (total, item) => total + item.precio_unitario * item.cantidad,
          0,
        ),
    );
  }

  private async resolveShippingAddress(
    id_usuario: number,
    dto: CreateCheckoutOrderDto,
    source: Queryable,
  ): Promise<number> {
    if (dto.id_direccion_envio) {
      const rows = await source.query(
        `
        SELECT id_direccion
        FROM core.direcciones
        WHERE id_direccion = $1
          AND id_usuario = $2
        LIMIT 1;
        `,
        [dto.id_direccion_envio, id_usuario],
      );

      if (!rows[0]) {
        throw new BadRequestException('La dirección de envío no es válida');
      }

      return Number(rows[0].id_direccion);
    }

    if (!dto.direccion) {
      throw new BadRequestException('Selecciona o registra una dirección');
    }

    return await this.createAddress(id_usuario, dto.direccion, source);
  }

  private async createAddress(
    id_usuario: number,
    address: CheckoutAddressDto,
    source: Queryable,
  ): Promise<number> {
    const isPrincipal = address.principal === true;

    if (isPrincipal) {
      await source.query(
        `
        UPDATE core.direcciones
        SET principal = false
        WHERE id_usuario = $1;
        `,
        [id_usuario],
      );
    }

    const rows = await source.query(
      `
      INSERT INTO core.direcciones (
        id_usuario,
        alias,
        calle,
        numero,
        colonia,
        ciudad,
        estado,
        codigo_postal,
        pais,
        principal
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, 'México'), $10)
      RETURNING id_direccion;
      `,
      [
        id_usuario,
        address.alias || 'Principal',
        address.calle,
        address.numero || null,
        address.colonia || null,
        address.ciudad,
        address.estado,
        address.codigo_postal,
        address.pais || 'México',
        isPrincipal,
      ],
    );

    return Number(rows[0].id_direccion);
  }

  private async resolvePaymentMethod(
    id_usuario: number,
    dto: CreateCheckoutOrderDto,
    source: Queryable,
  ): Promise<ResolvedPaymentMethod> {
    if (String(dto.metodo_pago) !== 'tarjeta') {
      throw new BadRequestException('Por ahora solo se aceptan pagos con tarjeta');
    }

    if (dto.id_metodo_pago_usuario) {
      const rows = await source.query(
        `
        SELECT
          id_metodo_pago,
          marca,
          ultimos4,
          exp_mes,
          exp_anio
        FROM core.user_payment_methods
        WHERE id_metodo_pago = $1
          AND id_usuario = $2
          AND activo = true
        LIMIT 1;
        `,
        [dto.id_metodo_pago_usuario, id_usuario],
      );

      const method = rows[0];

      if (!method) {
        throw new BadRequestException('La tarjeta seleccionada no es válida');
      }

      this.assertExpiryIsValid(Number(method.exp_mes), Number(method.exp_anio));

      return {
        id_metodo_pago: Number(method.id_metodo_pago),
        marca: method.marca || 'tarjeta',
        ultimos4: String(method.ultimos4 || '').padStart(4, '0'),
        referencia: this.buildPaymentReference(method.marca, method.ultimos4),
      };
    }

    if (!dto.tarjeta) {
      throw new BadRequestException('Agrega o selecciona una tarjeta');
    }

    const normalizedNumber = this.normalizeCardNumber(dto.tarjeta.numero);
    this.validateCardData(dto.tarjeta, normalizedNumber);

    const marca = this.detectCardBrand(normalizedNumber);
    const ultimos4 = normalizedNumber.slice(-4);
    let savedMethod: any = null;

    if (dto.guardar_tarjeta !== false) {
      savedMethod = await this.createPaymentMethodRecord(
        id_usuario,
        dto.tarjeta,
        source,
      );
    }

    return {
      id_metodo_pago: savedMethod?.id_metodo_pago,
      marca: savedMethod?.marca || marca,
      ultimos4: savedMethod?.ultimos4 || ultimos4,
      referencia: this.buildPaymentReference(marca, ultimos4),
    };
  }

  private async createPaymentMethodRecord(
    id_usuario: number,
    card: CheckoutCardDto,
    source: Queryable,
  ): Promise<any> {
    const normalizedNumber = this.normalizeCardNumber(card.numero);
    this.validateCardData(card, normalizedNumber);

    const marca = this.detectCardBrand(normalizedNumber);
    const ultimos4 = normalizedNumber.slice(-4);
    const fingerprint = this.getCardFingerprint(id_usuario, normalizedNumber);
    const titular = this.sanitizeCardHolder(card.titular);
    const alias = this.sanitizeText(card.alias, 60) || `${marca} ${ultimos4}`;
    const isPrincipal = card.principal !== false;

    if (isPrincipal) {
      await source.query(
        `
        UPDATE core.user_payment_methods
        SET principal = false,
            fecha_actualizacion = CURRENT_TIMESTAMP
        WHERE id_usuario = $1
          AND activo = true;
        `,
        [id_usuario],
      );
    }

    const existingRows = await source.query(
      `
      SELECT id_metodo_pago
      FROM core.user_payment_methods
      WHERE id_usuario = $1
        AND fingerprint = $2
        AND activo = true
      LIMIT 1;
      `,
      [id_usuario, fingerprint],
    );

    if (existingRows[0]) {
      const rows = await source.query(
        `
        UPDATE core.user_payment_methods
        SET alias = $3,
            titular = $4,
            exp_mes = $5,
            exp_anio = $6,
            marca = $7,
            ultimos4 = $8,
            principal = $9,
            fecha_actualizacion = CURRENT_TIMESTAMP
        WHERE id_metodo_pago = $1
          AND id_usuario = $2
        RETURNING
          id_metodo_pago,
          id_usuario,
          alias,
          'tarjeta' AS tipo,
          marca,
          titular,
          ultimos4,
          exp_mes,
          exp_anio,
          principal,
          activo,
          fecha_creacion,
          fecha_actualizacion;
        `,
        [
          Number(existingRows[0].id_metodo_pago),
          id_usuario,
          alias,
          titular,
          Number(card.exp_mes),
          Number(card.exp_anio),
          marca,
          ultimos4,
          isPrincipal,
        ],
      );

      return this.normalizePaymentMethodRow(rows[0]);
    }

    const rows = await source.query(
      `
      INSERT INTO core.user_payment_methods (
        id_usuario,
        alias,
        marca,
        titular,
        ultimos4,
        exp_mes,
        exp_anio,
        token_pago,
        fingerprint,
        principal,
        activo,
        fecha_creacion,
        fecha_actualizacion
      )
      VALUES (
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        $8,
        $9,
        $10,
        true,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
      )
      RETURNING
        id_metodo_pago,
        id_usuario,
        alias,
        'tarjeta' AS tipo,
        marca,
        titular,
        ultimos4,
        exp_mes,
        exp_anio,
        principal,
        activo,
        fecha_creacion,
        fecha_actualizacion;
      `,
      [
        id_usuario,
        alias,
        marca,
        titular,
        ultimos4,
        Number(card.exp_mes),
        Number(card.exp_anio),
        `SC_CARD_${randomUUID()}`,
        fingerprint,
        isPrincipal,
      ],
    );

    return this.normalizePaymentMethodRow(rows[0]);
  }

  private normalizePaymentMethodRow(row: any): any {
    return {
      ...row,
      tipo: row.tipo || 'tarjeta',
      id_metodo_pago: Number(row.id_metodo_pago),
      id_usuario: Number(row.id_usuario),
      exp_mes: Number(row.exp_mes),
      exp_anio: Number(row.exp_anio),
      principal: row.principal === true,
      activo: row.activo === true,
    };
  }

  private normalizeCardNumber(value: string): string {
    return String(value || '').replace(/\D/g, '');
  }

  private validateCardData(card: CheckoutCardDto, normalizedNumber: string): void {
    const titular = this.sanitizeCardHolder(card.titular);

    if (!titular) {
      throw new BadRequestException('El titular de la tarjeta es obligatorio');
    }

    if (!/^\d{13,19}$/.test(normalizedNumber) || !this.isValidLuhn(normalizedNumber)) {
      throw new BadRequestException('El número de tarjeta no es válido');
    }

    if (!/^\d{3,4}$/.test(String(card.cvv || ''))) {
      throw new BadRequestException('El CVV no es válido');
    }

    this.assertExpiryIsValid(Number(card.exp_mes), Number(card.exp_anio));
  }

  private assertExpiryIsValid(expMes: number, expAnio: number): void {
    if (!Number.isInteger(expMes) || expMes < 1 || expMes > 12) {
      throw new BadRequestException('El mes de vencimiento no es válido');
    }

    const now = new Date();
    const currentYear = now.getFullYear();
    const currentMonth = now.getMonth() + 1;

    if (
      !Number.isInteger(expAnio) ||
      expAnio < currentYear ||
      (expAnio === currentYear && expMes < currentMonth)
    ) {
      throw new BadRequestException('La tarjeta está vencida');
    }
  }

  private isValidLuhn(number: string): boolean {
    let sum = 0;
    let shouldDouble = false;

    for (let index = number.length - 1; index >= 0; index--) {
      let digit = Number(number[index]);

      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) {
          digit -= 9;
        }
      }

      sum += digit;
      shouldDouble = !shouldDouble;
    }

    return sum > 0 && sum % 10 === 0;
  }

  private detectCardBrand(number: string): string {
    if (/^4/.test(number)) {
      return 'Visa';
    }

    if (/^(5[1-5]|2[2-7])/.test(number)) {
      return 'Mastercard';
    }

    if (/^3[47]/.test(number)) {
      return 'American Express';
    }

    return 'Tarjeta';
  }

  private sanitizeCardHolder(value: string): string {
    return this.sanitizeText(value, 120).replace(/[^A-Za-zÁÉÍÓÚÜÑáéíóúüñ .'-]/g, '');
  }

  private sanitizeText(value: string | undefined, maxLength: number): string {
    return String(value || '')
      .trim()
      .replace(/[<>`{}\[\]\\|]/g, '')
      .replace(/\s+/g, ' ')
      .slice(0, maxLength);
  }

  private getCardFingerprint(id_usuario: number, number: string): string {
    return createHash('sha256')
      .update(`${id_usuario}:${number}`)
      .digest('hex');
  }

  private buildPaymentReference(marca: string, ultimos4: string): string {
    const cleanBrand = String(marca || 'tarjeta')
      .replace(/[^A-Za-z0-9]/g, '')
      .toUpperCase();
    const last4 = String(ultimos4 || '').replace(/\D/g, '').slice(-4);

    return `CARD-${cleanBrand}-${last4}-${Date.now().toString(36).toUpperCase()}`;
  }

  private buildMercadoPagoExternalReference(idOrden: number): string {
    return `SC-ORDER-${idOrden}-${randomUUID()}`;
  }

  private async createMercadoPagoPreference(input: {
    idOrden: number;
    externalReference: string;
    items: any[];
    totals: CheckoutTotals;
    shippingMethod: any;
    idUsuario: number;
  }): Promise<MercadoPagoPreference> {
    const accessToken = this.configService.get<string>('MERCADO_PAGO_ACCESS_TOKEN');

    if (!accessToken) {
      throw new BadRequestException(
        'Mercado Pago no está configurado en el servidor',
      );
    }

    const frontendUrl = this.normalizeBaseUrl(
      this.configService.get<string>('FRONTEND_URL') || 'http://localhost:4200',
    );
    const backendUrl = this.normalizeBaseUrl(
      this.configService.get<string>('BACKEND_PUBLIC_URL') || 'http://localhost:3000',
    );
    const notificationUrl =
      this.configService.get<string>('MERCADO_PAGO_WEBHOOK_URL') ||
      `${backendUrl}/products/checkout/mercado-pago/webhook`;
    const successUrl = `${frontendUrl}/dashboard/usuario/compras?payment=success&order=${input.idOrden}`;
    const failureUrl = `${frontendUrl}/dashboard/usuario/compras?payment=failure&order=${input.idOrden}`;
    const pendingUrl = `${frontendUrl}/dashboard/usuario/compras?payment=pending&order=${input.idOrden}`;
    const preferencePayload: Record<string, any> = {
      items: [
        {
          id: String(input.idOrden),
          title: `Pedido Sport Center #${input.idOrden}`,
          description: `${input.totals.itemCount} producto(s) con ${input.shippingMethod?.nombre || 'envío estándar'}`,
          quantity: 1,
          unit_price: input.totals.total,
          currency_id: 'MXN',
        },
      ],
      external_reference: input.externalReference,
      back_urls: {
        success: successUrl,
        failure: failureUrl,
        pending: pendingUrl,
      },
      metadata: {
        id_orden: input.idOrden,
        id_usuario: input.idUsuario,
        external_reference: input.externalReference,
      },
    };

    if (this.isPublicUrl(frontendUrl)) {
      preferencePayload.auto_return = 'approved';
    }

    if (this.isPublicUrl(notificationUrl)) {
      preferencePayload.notification_url = notificationUrl;
    }

    try {
      const response = await axios.post(
        'https://api.mercadopago.com/checkout/preferences',
        preferencePayload,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          timeout: 10000,
        },
      );

      return {
        id: response.data?.id,
        init_point: response.data?.init_point,
        sandbox_init_point: response.data?.sandbox_init_point,
      };
    } catch (error: any) {
      this.logger.error(
        'Error al crear preferencia de Mercado Pago:',
        error?.response?.data || error,
      );
      throw new BadRequestException(
        'No fue posible iniciar el pago con Mercado Pago',
      );
    }
  }

  private async getMercadoPagoPayment(paymentId: string): Promise<any> {
    const accessToken = this.configService.get<string>('MERCADO_PAGO_ACCESS_TOKEN');

    if (!accessToken) {
      throw new BadRequestException(
        'Mercado Pago no está configurado en el servidor',
      );
    }

    const response = await axios.get(
      `https://api.mercadopago.com/v1/payments/${encodeURIComponent(paymentId)}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
        timeout: 10000,
      },
    );

    return response.data;
  }

  private async syncMercadoPagoPayment(payment: any): Promise<void> {
    const externalReference =
      payment?.external_reference || payment?.metadata?.external_reference;

    if (!externalReference) {
      this.logger.warn('Pago de Mercado Pago sin referencia externa');
      return;
    }

    const mappedStatus = this.mapMercadoPagoStatus(payment?.status);
    const queryRunner = this.editorDataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const source = queryRunner.manager;
      const rows = await source.query(
        `
        SELECT
          p.id_pago,
          p.id_orden,
          p.estado AS estado_pago,
          o.estado AS estado_orden,
          o.id_usuario
        FROM core.pagos p
        INNER JOIN core.orders o
          ON o.id_orden = p.id_orden
        WHERE p.proveedor_pago = 'mercado_pago'
          AND p.referencia_externa = $1
        LIMIT 1
        FOR UPDATE;
        `,
        [externalReference],
      );

      const row = rows[0];
      if (!row) {
        this.logger.warn(
          `No se encontró pago local para Mercado Pago ${externalReference}`,
        );
        await queryRunner.commitTransaction();
        return;
      }

      await source.query(
        `
        UPDATE core.pagos
        SET estado = $2
        WHERE id_pago = $1;
        `,
        [row.id_pago, mappedStatus],
      );

      if (mappedStatus === 'aprobado' && row.estado_orden !== 'pendiente') {
        const stockResult = await this.deductInventoryForPaidOrder(
          Number(row.id_orden),
          source,
        );

        if (!stockResult.ok) {
          await source.query(
            `
            UPDATE core.orders
            SET estado = 'incidencia_stock',
                fecha_pago = COALESCE(fecha_pago, CURRENT_TIMESTAMP)
            WHERE id_orden = $1;
            `,
            [row.id_orden],
          );

          await this.saveOrderHistory(
            Number(row.id_orden),
            row.estado_orden,
            'incidencia_stock',
            stockResult.message || 'Pago aprobado, pero no hay stock suficiente',
            Number(row.id_usuario),
            source,
          );

          await queryRunner.commitTransaction();
          return;
        }

        await source.query(
          `
          UPDATE core.orders
          SET estado = 'pendiente',
              fecha_pago = COALESCE(fecha_pago, CURRENT_TIMESTAMP)
          WHERE id_orden = $1;
          `,
          [row.id_orden],
        );

        await this.applyPromotionRedemptionOnApproval(
          Number(row.id_orden),
          Number(row.id_usuario),
          source,
        );
        await this.clearCartItemsAfterPayment(
          Number(row.id_usuario),
          Number(row.id_orden),
          source,
        );

        await this.saveOrderHistory(
          Number(row.id_orden),
          row.estado_orden,
          'pendiente',
          'Pago aprobado por Mercado Pago',
          Number(row.id_usuario),
          source,
        );
      }

      if (
        ['rechazado', 'cancelado', 'reembolsado'].includes(mappedStatus) &&
        !['pago_rechazado', 'pago_cancelado', 'reembolsado'].includes(
          String(row.estado_orden || ''),
        )
      ) {
        const newOrderStatus =
          mappedStatus === 'reembolsado' ? 'reembolsado' : 'pago_rechazado';

        await source.query(
          `
          UPDATE core.orders
          SET estado = $2
          WHERE id_orden = $1;
          `,
          [row.id_orden, newOrderStatus],
        );

        await this.releaseReservedInventory(Number(row.id_orden), source);
        await this.saveOrderHistory(
          Number(row.id_orden),
          row.estado_orden,
          newOrderStatus,
          `Pago ${mappedStatus} por Mercado Pago`,
          Number(row.id_usuario),
          source,
        );
      }

      await queryRunner.commitTransaction();
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error('Error al sincronizar pago de Mercado Pago:', error);
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  private mapMercadoPagoStatus(status: string): string {
    const normalized = String(status || '').toLowerCase();

    if (normalized === 'approved') {
      return 'aprobado';
    }

    if (['pending', 'in_process', 'authorized'].includes(normalized)) {
      return 'pendiente';
    }

    if (['cancelled', 'canceled'].includes(normalized)) {
      return 'cancelado';
    }

    if (['refunded', 'charged_back'].includes(normalized)) {
      return 'reembolsado';
    }

    return 'rechazado';
  }

  private normalizeBaseUrl(value: string): string {
    return String(value || '').trim().replace(/\/+$/, '');
  }

  private isPublicUrl(value: string): boolean {
    try {
      const url = new URL(value);
      return (
        ['http:', 'https:'].includes(url.protocol) &&
        !['localhost', '127.0.0.1', '::1'].includes(url.hostname)
      );
    } catch {
      return false;
    }
  }

  private async deductInventoryForPaidOrder(
    idOrden: number,
    source: Queryable,
  ): Promise<{ ok: boolean; message?: string }> {
    const existingMovement = await source.query(
      `
      SELECT 1
      FROM core.inventory_movements
      WHERE referencia_tipo = 'orden'
        AND referencia_id = $1
        AND tipo = 'salida'
      LIMIT 1;
      `,
      [idOrden],
    );

    if (existingMovement[0]) {
      return { ok: true };
    }

    const items = await source.query(
      `
      SELECT
        oi.id_variante,
        oi.cantidad,
        oi.nombre_producto,
        COALESCE(i.costo_promedio, oi.precio_unitario, 0) AS costo_unitario
      FROM core.order_items oi
      LEFT JOIN core.inventory i
        ON i.id_variante = oi.id_variante
      WHERE oi.id_orden = $1;
      `,
      [idOrden],
    );

    for (const item of items) {
      const inventoryRows = await source.query(
        `
        UPDATE core.inventory
        SET stock_actual = stock_actual - $2
        WHERE id_variante = $1
          AND stock_actual >= $2
        RETURNING stock_actual;
        `,
        [item.id_variante, item.cantidad],
      );

      if (inventoryRows.length === 0) {
        return {
          ok: false,
          message: `No hay stock suficiente de "${item.nombre_producto}"`,
        };
      }

      await source.query(
        `
        INSERT INTO core.inventory_movements (
          id_variante,
          tipo,
          cantidad,
          costo_unitario,
          referencia_tipo,
          referencia_id
        )
        VALUES ($1, 'salida', $2, $3, 'orden', $4);
        `,
        [
          item.id_variante,
          item.cantidad,
          Number(item.costo_unitario || 0),
          idOrden,
        ],
      );
    }

    return { ok: true };
  }

  private async clearCartItemsAfterPayment(
    idUsuario: number,
    idOrden: number,
    source: Queryable,
  ): Promise<void> {
    const cartRows = await source.query(
      `
      SELECT id_carrito
      FROM core.carts
      WHERE id_usuario = $1
        AND LOWER(TRIM(estado)) = 'activo'
      ORDER BY fecha_actualizacion DESC NULLS LAST, fecha_creacion DESC
      LIMIT 1
      FOR UPDATE;
      `,
      [idUsuario],
    );

    const cart = cartRows[0];
    if (!cart) {
      return;
    }

    const cartColumn = await this.getCartItemCartColumn(source);
    const items = await source.query(
      `
      SELECT id_variante, cantidad
      FROM core.order_items
      WHERE id_orden = $1;
      `,
      [idOrden],
    );

    for (const item of items) {
      await source.query(
        `
        DELETE FROM core.cart_items
        WHERE ${cartColumn} = $1
          AND id_variante = $2
          AND cantidad <= $3;
        `,
        [cart.id_carrito, item.id_variante, item.cantidad],
      );

      await source.query(
        `
        UPDATE core.cart_items
        SET cantidad = cantidad - $3
        WHERE ${cartColumn} = $1
          AND id_variante = $2
          AND cantidad > $3;
        `,
        [cart.id_carrito, item.id_variante, item.cantidad],
      );
    }

    const remainingRows = await source.query(
      `
      SELECT COUNT(*)::int AS total
      FROM core.cart_items
      WHERE ${cartColumn} = $1;
      `,
      [cart.id_carrito],
    );

    if (Number(remainingRows[0]?.total || 0) === 0) {
      await source.query(
        `
        UPDATE core.carts
        SET estado = 'convertido',
            fecha_actualizacion = CURRENT_TIMESTAMP
        WHERE id_carrito = $1;
        `,
        [cart.id_carrito],
      );
    } else {
      await source.query(
        `
        UPDATE core.carts
        SET fecha_actualizacion = CURRENT_TIMESTAMP
        WHERE id_carrito = $1;
        `,
        [cart.id_carrito],
      );
    }
  }

  private async releaseReservedInventory(
    idOrden: number,
    source: Queryable,
  ): Promise<void> {
    const existingMovement = await source.query(
      `
      SELECT 1
      FROM core.inventory_movements
      WHERE referencia_tipo = 'orden'
        AND referencia_id = $1
        AND tipo = 'salida'
      LIMIT 1;
      `,
      [idOrden],
    );

    if (!existingMovement[0]) {
      return;
    }

    const items = await source.query(
      `
      SELECT id_variante, cantidad, precio_unitario
      FROM core.order_items
      WHERE id_orden = $1;
      `,
      [idOrden],
    );

    for (const item of items) {
      await source.query(
        `
        UPDATE core.inventory
        SET stock_actual = stock_actual + $2
        WHERE id_variante = $1;
        `,
        [item.id_variante, item.cantidad],
      );

      await source.query(
        `
        INSERT INTO core.inventory_movements (
          id_variante,
          tipo,
          cantidad,
          costo_unitario,
          referencia_tipo,
          referencia_id
        )
        VALUES ($1, 'entrada', $2, $3, 'pago_rechazado', $4);
        `,
        [
          item.id_variante,
          item.cantidad,
          Number(item.precio_unitario || 0),
          idOrden,
        ],
      );
    }
  }

  private async saveMercadoPagoPayment(
    idOrden: number,
    total: number,
    externalReference: string,
    source: Queryable,
  ): Promise<void> {
    await source.query(
      `
      INSERT INTO core.pagos (
        id_orden,
        proveedor_pago,
        referencia_externa,
        monto,
        estado,
        fecha_creacion
      )
      VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP);
      `,
      [idOrden, 'mercado_pago', externalReference, total, 'pendiente'],
    );
  }

  private async saveShipment(
    idOrden: number,
    idUsuario: number,
    shippingMethod: any,
    shippingCost: number,
    source: Queryable,
  ): Promise<void> {
    const rows = await source.query(
      `
      INSERT INTO core.shipments (
        id_orden,
        id_metodo_envio,
        estado,
        costo_envio,
        fecha_entrega_estimada,
        creado_por,
        actualizado_por,
        fecha_creacion,
        fecha_actualizacion
      )
      VALUES (
        $1,
        $2,
        'pendiente',
        $3,
        CURRENT_TIMESTAMP + ($4::int * INTERVAL '1 day'),
        $5,
        $5,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
      )
      RETURNING id_envio;
      `,
      [
        idOrden,
        shippingMethod?.id_metodo_envio || null,
        shippingCost,
        Number(shippingMethod?.dias_max || 5),
        idUsuario,
      ],
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
      VALUES ($1, 'pendiente', 'Pedido recibido', 'El pedido fue registrado para preparación.', $2);
      `,
      [rows[0].id_envio, idUsuario],
    );
  }

  private async saveInitialOrderHistory(
    idOrden: number,
    idUsuario: number,
    source: Queryable,
  ): Promise<void> {
    await source.query(
      `
      INSERT INTO core.order_status_history (
        id_orden,
        estado_anterior,
        estado_nuevo,
        comentario,
        cambiado_por
      )
      VALUES ($1, NULL, 'pendiente_pago', 'Pedido creado desde checkout, esperando confirmación de Mercado Pago', $2);
      `,
      [idOrden, idUsuario],
    );
  }

  private async saveOrderHistory(
    idOrden: number,
    previousStatus: string | null,
    nextStatus: string,
    comment: string,
    idUsuario: number,
    source: Queryable,
  ): Promise<void> {
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
      [idOrden, previousStatus || null, nextStatus, comment, idUsuario],
    );
  }

  private async savePromotionUsage(
    idUsuario: number,
    idOrden: number,
    promotion: PromotionResult | null,
    code: string | undefined,
    source: Queryable,
  ): Promise<void> {
    if (!promotion) {
      return;
    }

    if (promotion.descuento > 0 || promotion.envioGratis) {
      await source.query(
        `
        INSERT INTO core.order_discounts (
          id_orden,
          id_promocion,
          codigo,
          descripcion,
          monto
        )
        VALUES ($1, $2, $3, $4, $5);
        `,
        [
          idOrden,
          promotion.id_promocion,
          promotion.codigo || code || null,
          promotion.envioGratis
            ? 'Promoción de envío gratis'
            : promotion.nombre,
          promotion.descuento,
        ],
      );
    }

    return;
  }

  private async applyPromotionRedemptionOnApproval(
    idOrden: number,
    idUsuario: number,
    source: Queryable,
  ): Promise<void> {
    const discounts = await source.query(
      `
      SELECT id_promocion, codigo, monto
      FROM core.order_discounts
      WHERE id_orden = $1
        AND id_promocion IS NOT NULL;
      `,
      [idOrden],
    );

    for (const discount of discounts) {
      await source.query(
        `
        INSERT INTO core.promotion_redemptions (
          id_promocion,
          id_usuario,
          id_orden,
          codigo_usado,
          descuento_aplicado
        )
        SELECT $1, $2, $3, $4, $5
        WHERE NOT EXISTS (
          SELECT 1
          FROM core.promotion_redemptions
          WHERE id_promocion = $1
            AND id_usuario = $2
            AND id_orden = $3
        );
        `,
        [
          discount.id_promocion,
          idUsuario,
          idOrden,
          discount.codigo || null,
          Number(discount.monto || 0),
        ],
      );
    }
  }

  private roundMoney(value: number): number {
    return Math.round((Number(value || 0) + Number.EPSILON) * 100) / 100;
  }
}
