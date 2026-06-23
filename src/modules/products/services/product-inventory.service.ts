/* eslint-disable */
import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { CreateInventoryMovementDto } from '../dto/inventory/create-inventory_movement.dto';
import { CreateInventoryMovementSkuDto } from '../dto/inventory/create-inventory-movement-sku.dto';
import { Inventory } from '../entities/inventory/inventory.entity';
import { InventoryMovements } from '../entities/inventory/inventory_movements.entity';
import { Product } from '../entities/product/product.entity';
import { ProductVariant } from '../entities/product/product_variant.entity';

@Injectable()
export class ProductInventoryService {
  private readonly logger = new Logger(ProductInventoryService.name);

  constructor(
    @InjectRepository(Product, 'editorConnection')
    private readonly productEditorRepository: Repository<Product>,
    @InjectRepository(Inventory, 'editorConnection')
    private readonly inventoryEditorRepository: Repository<Inventory>,
    @InjectRepository(InventoryMovements, 'editorConnection')
    private readonly inventoryMovementsEditorRepository: Repository<InventoryMovements>,

    @InjectRepository(Product, 'readerConnection')
    private readonly productReaderRepository: Repository<Product>,
    @InjectRepository(ProductVariant, 'readerConnection')
    private readonly productVariantReaderRepository: Repository<ProductVariant>,
    @InjectRepository(Inventory, 'readerConnection')
    private readonly inventoryReaderRepository: Repository<Inventory>,
    @InjectRepository(InventoryMovements, 'readerConnection')
    private readonly inventoryMovementsReaderRepository: Repository<InventoryMovements>,
  ) {}

  async getInventoryProducts(): Promise<any[]> {
    try {
      const result = await this.productReaderRepository.query(`
        SELECT
          inv.*,
          COALESCE(variant_image.imagenes->>0, '') AS imagen_producto,
          COALESCE(inv.imagen, '') AS imagen_marca
        FROM core.get_inventory_products() inv
        LEFT JOIN LATERAL (
          SELECT pv.imagenes
          FROM core.product_variants pv
          WHERE pv.id_producto = inv.id_producto
            AND jsonb_typeof(pv.imagenes) = 'array'
            AND jsonb_array_length(pv.imagenes) > 0
          ORDER BY pv.id_variante ASC
          LIMIT 1
        ) variant_image ON TRUE;
      `);
      return result;
    } catch (error) {
      this.logger.error('ERROR REAL:', error);
      throw error;
    }
  }

  async updateProductInv(dto: {
    id_producto: number;
    estado: boolean;
  }): Promise<number> {
    try {
      const product = await this.productReaderRepository.findOne({
        where: { id_producto: dto.id_producto },
      });

      if (!product) {
        throw new BadRequestException('Producto no encontrado');
      }

      if (dto.estado) {
        const inventorySummary = await this.productReaderRepository.query(
          `
          SELECT id_producto, precio, stock
          FROM core.get_inventory_products()
          WHERE id_producto = $1
          LIMIT 1;
          `,
          [dto.id_producto],
        );

        const currentInventory = inventorySummary[0];
        const stock = currentInventory?.stock
          ? Number(currentInventory.stock)
          : 0;
        const precio = currentInventory?.precio
          ? Number(currentInventory.precio)
          : 0;

        if (stock <= 0) {
          throw new BadRequestException(
            'No se puede activar el producto porque no tiene stock disponible',
          );
        }

        if (precio <= 0) {
          throw new BadRequestException(
            'No se puede activar el producto porque no tiene precio configurado',
          );
        }
      }

      product.activo = dto.estado;

      await this.productEditorRepository.save(product);

      return 1;
    } catch (error) {
      throw error;
    }
  }

  async createInventoryMovementBySku(
    dto: CreateInventoryMovementSkuDto,
  ): Promise<InventoryMovements> {
    try {
      const variant = await this.productVariantReaderRepository.findOne({
        where: { sku: dto.sku },
      });

      if (!variant) {
        throw new BadRequestException(
          `No se encontró ninguna variante con el SKU: ${dto.sku}`,
        );
      }

      const inventory = await this.inventoryReaderRepository.findOne({
        where: { id_variante: variant.id_variante },
      });

      if (!inventory) {
        throw new BadRequestException(
          `No hay inventario registrado para la variante con SKU: ${dto.sku}`,
        );
      }

      if (
        dto.tipo.toLowerCase() === 'salida' &&
        inventory.stock_actual < dto.cantidad
      ) {
        throw new BadRequestException(
          `Stock insuficiente. Disponible: ${inventory.stock_actual}, Solicitado: ${dto.cantidad}`,
        );
      }

      const movementData = {
        id_variante: variant.id_variante,
        tipo: dto.tipo,
        cantidad:
          dto.tipo.toLowerCase() === 'salida'
            ? -Math.abs(dto.cantidad)
            : dto.cantidad,
        costo_unitario: dto.costo_unitario || 0,
        referencia_tipo: dto.referencia_tipo || 'manual',
        referencia_id: dto.referencia_id || 0,
      };

      const movement =
        this.inventoryMovementsEditorRepository.create(movementData);
      await this.inventoryMovementsEditorRepository.save(movement);

      if (dto.tipo.toLowerCase() === 'salida') {
        inventory.stock_actual -= dto.cantidad;
      } else {
        inventory.stock_actual += dto.cantidad;
      }

      await this.inventoryEditorRepository.save(inventory);

      return {
        ...movement,
        sku: variant.sku,
        producto_id: variant.id_producto,
      } as any;
    } catch (error) {
      this.logger.error('Error al crear movimiento:', error);
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new BadRequestException('Error al crear movimiento de inventario');
    }
  }

  async createInventoryMovement(
    dto: CreateInventoryMovementDto,
  ): Promise<InventoryMovements> {
    try {
      const inventory = await this.inventoryReaderRepository.findOne({
        where: { id_variante: dto.id_variante },
      });

      if (!inventory) {
        throw new BadRequestException('Inventario no encontrado');
      }

      const movement = this.inventoryMovementsEditorRepository.create(dto);
      await this.inventoryMovementsEditorRepository.save(movement);

      inventory.stock_actual += dto.cantidad;
      await this.inventoryEditorRepository.save(inventory);

      return movement;
    } catch (error) {
      this.logger.error('Error al crear movimiento:', error);
      throw new BadRequestException('Error al crear movimiento de inventario');
    }
  }

  async bulkCreateInventoryMovements(
    movements: CreateInventoryMovementSkuDto[],
  ): Promise<{ success: number; errors: any[] }> {
    const results = {
      success: 0,
      errors: [] as any[],
    };

    for (const [index, movement] of movements.entries()) {
      try {
        await this.createInventoryMovementBySku(movement);
        results.success++;
      } catch (error) {
        results.errors.push({
          row: index + 2,
          sku: movement.sku,
          error: error.message,
          data: movement,
        });
      }
    }

    return results;
  }

  async getInventoryMovements(): Promise<InventoryMovements[]> {
    try {
      const movements = await this.inventoryMovementsReaderRepository.query(`
        SELECT
          m.*,
          COALESCE(pv.imagenes, '[]'::jsonb) AS imagenes_variante,
          COALESCE(pv.imagenes->>0, '') AS imagen_variante
        FROM core.get_inventory_movements() m
        LEFT JOIN core.product_variants pv
          ON pv.id_variante = m.id_variante
      `);

      return movements;
    } catch (error) {
      this.logger.error('Error al obtener movimientos de inventario:', error);
      throw new BadRequestException(
        'Error al obtener movimientos de inventario',
        error,
      );
    }
  }

  async getVariantsForInventoryMovement(): Promise<any[]> {
    try {
      return await this.productVariantReaderRepository.query(`
        SELECT
          pv.id_variante,
          pv.id_producto,
          pv.sku,
          pv.precio,
          COALESCE(i.stock_actual, 0) AS stock_actual,
          p.nombre AS producto,
          m.nombre AS marca,
          COALESCE(pv.imagenes, '[]'::jsonb) AS imagenes,
          COALESCE(pv.imagenes->>0, '') AS imagen
        FROM core.product_variants pv
        INNER JOIN core.products p
          ON p.id_producto = pv.id_producto
        LEFT JOIN core.marcas m
          ON m.id_marca = p.id_marca
        LEFT JOIN core.inventory i
          ON i.id_variante = pv.id_variante
        ORDER BY
          CASE WHEN COALESCE(i.stock_actual, 0) = 0 THEN 0 ELSE 1 END ASC,
          COALESCE(i.stock_actual, 0) ASC,
          p.nombre ASC,
          pv.sku ASC;
      `);
    } catch (error) {
      this.logger.error(
        'Error al obtener variantes para movimientos de inventario:',
        error,
      );
      throw new BadRequestException(
        'Error al obtener variantes para movimientos de inventario',
      );
    }
  }
}
