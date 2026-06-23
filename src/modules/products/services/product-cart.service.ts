/* eslint-disable */
import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

import { AddCartItemDto } from '../dto/cart/add-cart-item.dto';
import { UpdateCartItemDto } from '../dto/cart/update-cart-item.dto';

type CartItemCartColumn = 'id_carrito' | 'id_carrto';

@Injectable()
export class ProductCartService {
  private readonly logger = new Logger(ProductCartService.name);
  private cartItemCartColumn?: CartItemCartColumn;

  constructor(
    @InjectDataSource('readerConnection')
    private readonly readerDataSource: DataSource,
    @InjectDataSource('editorConnection')
    private readonly editorDataSource: DataSource,
  ) {}

  private validateUser(id_usuario: number): void {
    if (!Number.isInteger(id_usuario) || id_usuario <= 0) {
      throw new BadRequestException('El usuario debe ser válido');
    }
  }

  private validateVariant(id_variante: number): void {
    if (!Number.isInteger(id_variante) || id_variante <= 0) {
      throw new BadRequestException('La variante debe ser válida');
    }
  }

  private async getCartItemCartColumn(): Promise<CartItemCartColumn> {
    if (this.cartItemCartColumn) {
      return this.cartItemCartColumn;
    }

    const rows = await this.readerDataSource.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'core'
        AND table_name = 'cart_items'
        AND column_name IN ('id_carrito', 'id_carrto')
      ORDER BY CASE WHEN column_name = 'id_carrito' THEN 0 ELSE 1 END
      LIMIT 1;
    `);

    const column = rows?.[0]?.column_name;

    if (column === 'id_carrito' || column === 'id_carrto') {
      this.cartItemCartColumn = column;
      return column;
    }

    this.cartItemCartColumn = 'id_carrito';
    return this.cartItemCartColumn;
  }

  private async ensureActiveCart(id_usuario: number): Promise<any> {
    this.validateUser(id_usuario);

    const existing = await this.editorDataSource.query(
      `
      SELECT
        id_carrito,
        id_usuario,
        estado,
        fecha_creacion,
        fecha_actualizacion
      FROM core.carts
      WHERE id_usuario = $1
        AND LOWER(TRIM(estado)) = 'activo'
      ORDER BY fecha_actualizacion DESC NULLS LAST, fecha_creacion DESC
      LIMIT 1;
      `,
      [id_usuario],
    );

    if (existing.length > 0) {
      return existing[0];
    }

    const inserted = await this.editorDataSource.query(
      `
      INSERT INTO core.carts (
        id_usuario,
        estado,
        fecha_creacion,
        fecha_actualizacion
      )
      VALUES ($1, 'activo', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      RETURNING
        id_carrito,
        id_usuario,
        estado,
        fecha_creacion,
        fecha_actualizacion;
      `,
      [id_usuario],
    );

    return inserted[0];
  }

  private async touchCart(id_carrito: number): Promise<void> {
    await this.editorDataSource.query(
      `
      UPDATE core.carts
      SET fecha_actualizacion = CURRENT_TIMESTAMP
      WHERE id_carrito = $1;
      `,
      [id_carrito],
    );
  }

  private async getVariantForCart(id_variante: number, quantity: number): Promise<any> {
    this.validateVariant(id_variante);

    if (!Number.isInteger(quantity) || quantity <= 0 || quantity > 99) {
      throw new BadRequestException('La cantidad debe estar entre 1 y 99');
    }

    const rows = await this.readerDataSource.query(
      `
      SELECT
        pv.id_variante,
        pv.id_producto,
        pv.sku,
        pv.precio,
        pv.imagenes,
        pv.atributos,
        p.nombre,
        p.activo,
        COALESCE(i.stock_actual, 0)::int AS stock
      FROM core.product_variants pv
      INNER JOIN core.products p
        ON p.id_producto = pv.id_producto
      LEFT JOIN core.inventory i
        ON i.id_variante = pv.id_variante
      WHERE pv.id_variante = $1
      LIMIT 1;
      `,
      [id_variante],
    );

    const variant = rows[0];

    if (!variant) {
      throw new BadRequestException('La variante no existe');
    }

    if (variant.activo !== true) {
      throw new BadRequestException('Este producto no está disponible');
    }

    const stock = Number(variant.stock || 0);
    if (stock <= 0) {
      throw new BadRequestException('Este producto no tiene stock disponible');
    }

    if (quantity > stock) {
      throw new BadRequestException(`Solo hay ${stock} unidades disponibles`);
    }

    return {
      ...variant,
      stock,
      precio: Number(variant.precio || 0),
    };
  }

  private normalizeCartItems(items: any[]): any[] {
    return items.map((item) => {
      const imagenes = Array.isArray(item.imagenes) ? item.imagenes : [];
      const atributos =
        item.atributos && typeof item.atributos === 'object'
          ? item.atributos
          : {};

      return {
        ...item,
        id_carrito: Number(item.id_carrito),
        id_variante: Number(item.id_variante),
        id_producto: Number(item.id_producto),
        cantidad: Number(item.cantidad || 0),
        precio_unitario: Number(item.precio_unitario || 0),
        precio: Number(item.precio || item.precio_unitario || 0),
        stock: Number(item.stock || 0),
        imagenes,
        imagen: imagenes[0] ?? null,
        atributos,
      };
    });
  }

  private buildSummary(items: any[]) {
    const subtotal = items.reduce(
      (total, item) => total + item.precio_unitario * item.cantidad,
      0,
    );
    const itemCount = items.reduce((total, item) => total + item.cantidad, 0);

    return {
      subtotal,
      itemCount,
    };
  }

  private async buildCartResponse(
    id_usuario: number,
    dataSource?: DataSource,
  ): Promise<any> {
    const source = dataSource ?? this.readerDataSource;
    const cart = await this.ensureActiveCart(id_usuario);
    const cartColumn = await this.getCartItemCartColumn();

    const items = await source.query(
      `
      SELECT
        ci.${cartColumn} AS id_carrito,
        ci.id_variante,
        ci.cantidad,
        ci.precio_unitario,
        pv.id_producto,
        pv.sku,
        pv.precio,
        pv.imagenes,
        pv.atributos,
        p.nombre,
        p.descripcion,
        p.activo,
        c.nombre AS categoria,
        m.nombre AS marca,
        m.imagen AS imagen_marca,
        COALESCE(i.stock_actual, 0)::int AS stock
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
      ORDER BY p.nombre ASC, pv.sku ASC;
      `,
      [cart.id_carrito],
    );

    const normalizedItems = this.normalizeCartItems(items);

    return {
      id_carrito: Number(cart.id_carrito),
      id_usuario: Number(cart.id_usuario),
      estado: cart.estado,
      fecha_creacion: cart.fecha_creacion,
      fecha_actualizacion: cart.fecha_actualizacion,
      items: normalizedItems,
      summary: this.buildSummary(normalizedItems),
    };
  }

  async getCart(id_usuario: number): Promise<any> {
    try {
      this.validateUser(id_usuario);
      return await this.buildCartResponse(id_usuario);
    } catch (error) {
      this.logger.error('Error al consultar carrito:', error);
      throw error;
    }
  }

  async addItem(id_usuario: number, dto: AddCartItemDto): Promise<any> {
    try {
      this.validateUser(id_usuario);
      const cart = await this.ensureActiveCart(id_usuario);
      const cartColumn = await this.getCartItemCartColumn();

      const existing = await this.editorDataSource.query(
        `
        SELECT cantidad
        FROM core.cart_items
        WHERE ${cartColumn} = $1
          AND id_variante = $2
        LIMIT 1;
        `,
        [cart.id_carrito, dto.id_variante],
      );

      const currentQuantity = Number(existing?.[0]?.cantidad || 0);
      const nextQuantity = currentQuantity + dto.cantidad;
      const variant = await this.getVariantForCart(dto.id_variante, nextQuantity);

      if (existing.length > 0) {
        await this.editorDataSource.query(
          `
          UPDATE core.cart_items
          SET
            cantidad = $3,
            precio_unitario = $4
          WHERE ${cartColumn} = $1
            AND id_variante = $2;
          `,
          [cart.id_carrito, dto.id_variante, nextQuantity, variant.precio],
        );
      } else {
        await this.editorDataSource.query(
          `
          INSERT INTO core.cart_items (
            ${cartColumn},
            id_variante,
            cantidad,
            precio_unitario
          )
          VALUES ($1, $2, $3, $4);
          `,
          [cart.id_carrito, dto.id_variante, dto.cantidad, variant.precio],
        );
      }

      await this.touchCart(cart.id_carrito);
      return await this.buildCartResponse(id_usuario, this.editorDataSource);
    } catch (error) {
      this.logger.error('Error al agregar producto al carrito:', error);

      if (error instanceof BadRequestException) {
        throw error;
      }

      throw new BadRequestException('No fue posible agregar el producto al carrito');
    }
  }

  async updateItem(
    id_usuario: number,
    id_variante: number,
    dto: UpdateCartItemDto,
  ): Promise<any> {
    try {
      this.validateUser(id_usuario);
      this.validateVariant(id_variante);

      if (dto.cantidad <= 0) {
        return await this.removeItem(id_usuario, id_variante);
      }

      const cart = await this.ensureActiveCart(id_usuario);
      const cartColumn = await this.getCartItemCartColumn();
      const variant = await this.getVariantForCart(id_variante, dto.cantidad);

      const updated = await this.editorDataSource.query(
        `
        UPDATE core.cart_items
        SET
          cantidad = $3,
          precio_unitario = $4
        WHERE ${cartColumn} = $1
          AND id_variante = $2
        RETURNING id_variante;
        `,
        [cart.id_carrito, id_variante, dto.cantidad, variant.precio],
      );

      if (updated.length === 0) {
        throw new BadRequestException('El producto no está en el carrito');
      }

      await this.touchCart(cart.id_carrito);
      return await this.buildCartResponse(id_usuario, this.editorDataSource);
    } catch (error) {
      this.logger.error('Error al actualizar carrito:', error);

      if (error instanceof BadRequestException) {
        throw error;
      }

      throw new BadRequestException('No fue posible actualizar el carrito');
    }
  }

  async removeItem(id_usuario: number, id_variante: number): Promise<any> {
    try {
      this.validateUser(id_usuario);
      this.validateVariant(id_variante);

      const cart = await this.ensureActiveCart(id_usuario);
      const cartColumn = await this.getCartItemCartColumn();

      await this.editorDataSource.query(
        `
        DELETE FROM core.cart_items
        WHERE ${cartColumn} = $1
          AND id_variante = $2;
        `,
        [cart.id_carrito, id_variante],
      );

      await this.touchCart(cart.id_carrito);
      return await this.buildCartResponse(id_usuario, this.editorDataSource);
    } catch (error) {
      this.logger.error('Error al eliminar producto del carrito:', error);
      throw error;
    }
  }

  async clearCart(id_usuario: number): Promise<any> {
    try {
      this.validateUser(id_usuario);

      const cart = await this.ensureActiveCart(id_usuario);
      const cartColumn = await this.getCartItemCartColumn();

      await this.editorDataSource.query(
        `
        DELETE FROM core.cart_items
        WHERE ${cartColumn} = $1;
        `,
        [cart.id_carrito],
      );

      await this.touchCart(cart.id_carrito);
      return await this.buildCartResponse(id_usuario, this.editorDataSource);
    } catch (error) {
      this.logger.error('Error al vaciar carrito:', error);
      throw error;
    }
  }
}
