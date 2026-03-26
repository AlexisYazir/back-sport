/* eslint-disable */
import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { InjectRepository, InjectDataSource } from '@nestjs/typeorm';
import { Repository, DataSource, Not } from 'typeorm';

import { CreateProductDto } from './dto/product/create-product.dto';
import { CreateProductSportsDto } from './dto/product/create-product-sports.dto';
import { Product } from './entities/product/product.entity';
import { UpdateProductInvDto } from './dto/product/update-product-inv.dto';
import { UpdateProductFullDto } from './dto/product/update-product-full.dto';
import { UpdateProductResult } from './dto/product/update-product-full.dto';
import { UpdateProductVariantAttributeDto } from './dto/product/update.product-var-attr.dto';
import { UpdateProductVarAttResult } from './dto/product/update.product-var-attr.dto';

import { CreateProductVariantDto } from './dto/product/create-product_variant.dto';
import { ProductVariant } from './entities/product/product_variant.entity';

import { CreateVarAttributeValuesDto } from './dto/product/create-var-att_vls.dto';
import { VariantAttributeValue } from './entities/product/variant_attr_vals.entity';

import { CreateAttributeDto } from './dto/product/create-attribute.dto';
import { Attribute } from './entities/product/atributtes.entity';

import { Sports } from './entities/sports/sport.entity';
import { ProductSport } from './entities/sports/product-sport.entity';

import { CreateMarcaDto } from './dto/marca/create-marca.tdo';
import { UpdateMarcaDto } from './dto/marca/update-marca.dto';
import { Marca } from './entities/marca/marca.entity';

import { CreateCategorieDto } from './dto/categories/create-categorie.dto';
import { UpdateCategorieDto } from './dto/categories/update-categorie.dto';
import { Category } from './entities/categorie/categorie.entity';

import { Orders } from './entities/orders/orders.entity';

import { CreateInventoryMovementDto } from './dto/inventory/create-inventory_movement.dto';
import { CreateInventoryMovementSkuDto } from './dto/inventory/create-inventory-movement-sku.dto';
import { InventoryMovements } from './entities/inventory/inventory_movements.entity';
import { Inventory } from './entities/inventory/inventory.entity';
import {
  CloudinaryService,
  CloudinaryUploadResult,
} from './services/cloudinary.service';

export interface ExcelImportResult {
  success: number;
  errors: Array<{
    row: number;
    sku: string;
    error: string;
    data: any;
  }>;
  total: number;
}

@Injectable()
export class ProductsService {
  private readonly logger = new Logger(ProductsService.name);
  constructor(
    // Inyectar DataSource específico para cada conexión
    @InjectDataSource('editorConnection') // Importante: especificar la conexión
    private readonly editorDataSource: DataSource,
    
    @InjectDataSource('readerConnection')
    private readonly readerDataSource: DataSource,
    
    // EDITOR: Para operaciones CRUD normales (CREATE, UPDATE)
    @InjectRepository(Product, 'editorConnection')
    private readonly productEditorRepository: Repository<Product>,
    @InjectRepository(ProductVariant, 'editorConnection')
    private readonly productVariantEditorRepository: Repository<ProductVariant>,
    @InjectRepository(ProductSport, 'editorConnection')
    private readonly productSportEditorRepository: Repository<ProductSport>,
    @InjectRepository(VariantAttributeValue, 'editorConnection')
    private readonly variantAttributeValueEditorRepository: Repository<VariantAttributeValue>,
    @InjectRepository(Attribute, 'editorConnection')
    private readonly attributeEditorRepository: Repository<Attribute>,
    
    // READER: Para consultas de solo lectura (SELECT)
    @InjectRepository(Product, 'readerConnection')
    private readonly productReaderRepository: Repository<Product>,
    @InjectRepository(ProductVariant, 'readerConnection')
    private readonly productVariantReaderRepository: Repository<ProductVariant>,
    @InjectRepository(VariantAttributeValue, 'readerConnection')
    private readonly variantAttributeValueReaderRepository: Repository<VariantAttributeValue>,
    @InjectRepository(Attribute, 'readerConnection')
    private readonly attributeReaderRepository: Repository<Attribute>,
    @InjectRepository(Sports, 'readerConnection')
    private readonly sportReaderRepository: Repository<Sports>,
    
    // ADMIN: Para operaciones que requieren permisos especiales
    @InjectRepository(Product, 'adminConnection')
    private readonly productAdminRepository: Repository<Product>,
    
    //marcas
    @InjectRepository(Marca, 'editorConnection')
    private readonly marcaEditorRepository: Repository<Marca>,
    @InjectRepository(Marca, 'readerConnection')
    private readonly marcaReaderRepository: Repository<Marca>,
    
    //categorias
    @InjectRepository(Category, 'editorConnection')
    private readonly categoryEditorRepository: Repository<Category>,
    @InjectRepository(Category, 'readerConnection')
    private readonly categoryReaderRepository: Repository<Category>,
    
    //ordenes (solo lectura para empleados)
    @InjectRepository(Orders, 'readerConnection')
    private readonly ordersReaderRepository: Repository<Orders>,
    
    //Inventory
    @InjectRepository(Inventory, 'editorConnection')
    private readonly inventoryEditorRepository: Repository<Inventory>,
    @InjectRepository(InventoryMovements, 'editorConnection')
    private readonly inventoryMovementsEditorRepository: Repository<InventoryMovements>,
    @InjectRepository(Inventory, 'readerConnection')
    private readonly inventoryReaderRepository: Repository<Inventory>,
    @InjectRepository(InventoryMovements, 'readerConnection')
    private readonly inventoryMovementsReaderRepository: Repository<InventoryMovements>,
    private readonly cloudinaryService: CloudinaryService,
  ) {}

  //* ---------- FUNCIONES PARA PRODUCTOS
  //! funcion para registrar un producto (EDITOR - CREATE)
  async createProduct(createProductDto: CreateProductDto): Promise<Product> {
    try {
      const product = this.productEditorRepository.create({
        nombre: createProductDto.nombre,
        descripcion: createProductDto.descripcion,
        id_marca: createProductDto.id_marca,
        id_categoria: createProductDto.id_categoria,
        activo: false,
      });

      return await this.productEditorRepository.save(product);
    } catch (error) {
      this.logger.error('Error al crear producto: ', error);
      throw new BadRequestException('Error al crear el producto', error);
    }
  }

  async assignProductSports(dto: CreateProductSportsDto): Promise<{
    id_producto: number;
    deportes_asignados: number;
  }> {
    try {
      const product = await this.productReaderRepository.findOneBy({
        id_producto: dto.id_producto,
      });

      if (!product) {
        throw new BadRequestException('El producto no existe');
      }

      const sportIds = Array.from(
        new Set((dto.ids_deportes ?? []).map(Number).filter((id) => Number.isInteger(id) && id > 0)),
      );

      if (sportIds.length > 0) {
        const existingSports = await this.sportReaderRepository.query(
          `SELECT id_deporte FROM core.deportes WHERE id_deporte = ANY($1::int[])`,
          [sportIds],
        );

        if (existingSports.length !== sportIds.length) {
          throw new BadRequestException('Uno o mas deportes seleccionados no existen');
        }
      }

      await this.editorDataSource.transaction(async (manager) => {
        await manager.query(
          `DELETE FROM core.product_deportes WHERE id_producto = $1`,
          [dto.id_producto],
        );

        if (sportIds.length === 0) {
          return;
        }

        const values = sportIds
          .map((_, index) => `($1, $${index + 2})`)
          .join(', ');

        await manager.query(
          `INSERT INTO core.product_deportes (id_producto, id_deporte) VALUES ${values}`,
          [dto.id_producto, ...sportIds],
        );
      });

      return {
        id_producto: dto.id_producto,
        deportes_asignados: sportIds.length,
      };
    } catch (error) {
      this.logger.error('Error al asignar deportes al producto: ', error);

      if (error instanceof BadRequestException) {
        throw error;
      }

      throw new BadRequestException('Error al asignar deportes al producto');
    }
  }

  async uploadImage(
    file: Express.Multer.File,
    folder?: string,
  ): Promise<CloudinaryUploadResult> {
    try {
      return await this.cloudinaryService.uploadProductImage(file, folder);
    } catch (error) {
      this.logger.error('Error al subir imagen a Cloudinary: ', error);

      if (error instanceof BadRequestException) {
        throw error;
      }

      throw new BadRequestException('No se pudo subir la imagen a Cloudinary');
    }
  }

  //! funcion para registrar una variante de producto (EDITOR - CREATE)
  async createProductVariant(dto: CreateProductVariantDto): Promise<ProductVariant> {
    // READER para verificar existencia
    const product = await this.productReaderRepository.findOneBy({
      id_producto: dto.id_producto,
    });

    // READER para verificar SKU duplicado
    const variante = await this.productVariantReaderRepository.findOneBy({
      sku: dto.sku,
    });

    if(variante) {
      throw new BadRequestException("EL codigo ya existe");
    }

    if (!product) {
      throw new BadRequestException('El producto no existe');
    }

    const variant = this.productVariantEditorRepository.create({
      id_producto: dto.id_producto,
      sku: dto.sku,
      precio: dto.precio,
      imagenes: dto.imagenes ?? [],
      atributos: dto.atributos ?? {}
    });

    return await this.productVariantEditorRepository.save(variant);
  }

  //! funcion para registrar un atributo de producto (EDITOR - CREATE)
  async createAttribute(dto: CreateAttributeDto): Promise<Attribute> {
    // READER para verificar duplicado
    const attribute = await this.attributeReaderRepository.findOneBy({
      nombre: dto.nombre,
    });

    if (attribute) {
      throw new BadRequestException('El atributo ya existe');
    }

    const variant = this.attributeEditorRepository.create({
      nombre: dto.nombre,      
    });

    return await this.attributeEditorRepository.save(variant);
  }

  //! funcion para registrar los valores de los atributos de una variante (EDITOR - CREATE)
  async createVariantAttributeValue(dto: CreateVarAttributeValuesDto): Promise<VariantAttributeValue> {
    try {
      const attribute = this.variantAttributeValueEditorRepository.create({
        id_variante: dto.id_variante,
        id_atributo: dto.id_atributo,
        valor: dto.valor,
      });

      return await this.variantAttributeValueEditorRepository.save(attribute);
    } catch (error) {
      this.logger.error("Error al crear atributo de variante: ", error);
      throw new BadRequestException('Error al crear atributo de variante');
    }
  }

  //! funcion para consultar todos los productos (READER - SELECT)
  async getAllProducts(): Promise<any[]> {
    try {
      const result = await this.productReaderRepository.query(
        `SELECT * FROM core.get_all_products() WHERE activo=true`
      );
      return result;
    } catch (error) {
      this.logger.error('Error al cargar todos los productos: ', error);
      throw error;
    }
  }

  //! funcion para consultar todos los productos recientemente creados (READER - SELECT)
  async getRecientProducts(): Promise<any[]> {
    try {
      const result = await this.productReaderRepository.query(
        `SELECT * FROM core.get_recients_products();`
      );
      return result;
    } catch (error) {
      this.logger.error('ERROR REAL:', error);
      throw error;
    }
  }

  //! funcion para consultar productos variantes pero con atributos vacios (READER - SELECT)
  async getProductsWithoutVariantsAttributes(): Promise<any[]> {
    try {
      const result = await this.productReaderRepository.query(
        `SELECT * FROM core.get_products_with_variants_without_attributes();`
      );
      return result;
    } catch (error) {
      this.logger.error('Error al consultar productos variantes:', error);
      throw error;
    }
  }

  //! funcion para consultar las variantes de un producto (READER - SELECT)
  async getVariantsByProduct(id: number): Promise<any[]> {
    try {
      const variants = await this.productVariantReaderRepository.query(
        `SELECT * FROM core.get_variants_product_by_id($1)`,
        [id]
      );

      return variants;

    } catch (error) {
      this.logger.error("Error al consultar variantes de producto por id: ", error)
      throw new Error('Error fetching product variants');
    }
  }

  //! funcion para consultar todos los productos (READER - SELECT)
  async getProductDetail(id: number): Promise<any[]> {
    try {
      const result = await this.productReaderRepository.query(
        `SELECT * FROM core.get_all_products() where id_producto = ${id};`
      );
      return result;
    } catch (error) {
      this.logger.error("Error al cargar los detalles de un producto: ", error)
      throw error;
    }
  }

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
        [id]
      );
      return result;
    } catch (error) {
      this.logger.error("Error al cargar los detalles de venta: ", error)
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
      `
    )

    return result
  }

  //! funcion para consultar todos los productos (READER - SELECT)
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

  //! funcion para actualizar estado de un producto (EDITOR - UPDATE)
  async updateProductInv(dto: { id_producto: number, estado: boolean }): Promise<number> {
    try {
      // READER para verificar existencia
      const product = await this.productReaderRepository.findOne({
        where: { id_producto: dto.id_producto }
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
        const stock = currentInventory?.stock ? Number(currentInventory.stock) : 0;
        const precio = currentInventory?.precio ? Number(currentInventory.precio) : 0;

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
      
      await this.productEditorRepository.save(product); // EDITOR para UPDATE

      return 1;
    } catch (error) {
      throw error;
    }
  }

  //! funcion para actualizar datos generales de producto (EDITOR - UPDATE via función)
  async updateProductFull(dto: UpdateProductFullDto): Promise<UpdateProductResult> {
    // Usamos editorRepository para ejecutar la función que actualiza
    const result: UpdateProductResult[] = await this.productEditorRepository.query(
      `
      SELECT * FROM core.update_full_product(
        $1, $2, $3, $4, $5
      )
      `,
      [
        dto.id_producto,
        dto.id_marca,
        dto.id_categoria,
        dto.nombre,
        dto.descripcion,
      ]
    );

    return result[0];
  }

  //! Funcion para actualizar datos de producto: variante y atributos (EDITOR - UPDATE)
  async updateProductVariant(dto: UpdateProductVariantAttributeDto): Promise<UpdateProductVarAttResult> {
    // READER para verificar SKU duplicado
    const existingVariant = await this.productVariantReaderRepository.findOne({
      where: {
        sku: dto.sku,
        id_variante: Not(dto.id_variante)
      }
    });

    if (existingVariant) {
      throw new BadRequestException(
        'El SKU(Codigo) ya está en uso por otra variante'
      );
    }

    // EDITOR para ejecutar la función de actualización
    const result: UpdateProductVarAttResult[] = await this.productVariantEditorRepository.query(
      `
      SELECT * FROM core.update_product_variant(
        $1,
        $2, $3, $4, $5, $6
      )
      `,
      [
        dto.id_producto,

        dto.id_variante,
        dto.sku,
        JSON.stringify(dto.imagenes),
        dto.precio,
        JSON.stringify(dto.atributos)
      ]
    );

    return result[0];
  }

  //* ---------- FUNCIONES PARA INVENTARIO
  //! funcion para registrar movimientos y actualizar inventario (EDITOR - CREATE/UPDATE)
  async createInventoryMovementBySku(
    dto: CreateInventoryMovementSkuDto,
  ): Promise<InventoryMovements> {
    try {
      // 1. Buscar la variante por SKU
      const variant = await this.productVariantReaderRepository.findOne({
        where: { sku: dto.sku },
      });

      if (!variant) {
        throw new BadRequestException(`No se encontró ninguna variante con el SKU: ${dto.sku}`);
      }

      // 2. Verificar que existe inventario para esa variante
      const inventory = await this.inventoryReaderRepository.findOne({
        where: { id_variante: variant.id_variante },
      });

      if (!inventory) {
        throw new BadRequestException(
          `No hay inventario registrado para la variante con SKU: ${dto.sku}`
        );
      }

      // 3. Validar stock negativo en salidas
      if (dto.tipo.toLowerCase() === 'salida' && inventory.stock_actual < dto.cantidad) {
        throw new BadRequestException(
          `Stock insuficiente. Disponible: ${inventory.stock_actual}, Solicitado: ${dto.cantidad}`
        );
      }

      // 4. Crear el movimiento
    const movementData = {
      id_variante: variant.id_variante,
      tipo: dto.tipo,
      cantidad: dto.tipo.toLowerCase() === 'salida' ? -Math.abs(dto.cantidad) : dto.cantidad,
      costo_unitario: dto.costo_unitario || 0,
      referencia_tipo: dto.referencia_tipo || 'manual',
      referencia_id: dto.referencia_id || 0,
    };

    const movement = this.inventoryMovementsEditorRepository.create(movementData);
    await this.inventoryMovementsEditorRepository.save(movement);

      // 5. Actualizar stock
      if (dto.tipo.toLowerCase() === 'salida') {
        inventory.stock_actual -= dto.cantidad;
      } else {
        inventory.stock_actual += dto.cantidad;
      }
      
      await this.inventoryEditorRepository.save(inventory);

      // 6. Retornar movimiento con info adicional
      return {
        ...movement,
        sku: variant.sku,
        producto_id: variant.id_producto
      } as any;

    } catch (error) {
      this.logger.error('Error al crear movimiento:', error);
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new BadRequestException('Error al crear movimiento de inventario');
    }
  }

  //! funcion para crear movimientos de inventario
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

      // Para la función original, asumimos que cantidad positiva es entrada, negativa es salida
      inventory.stock_actual += dto.cantidad;
      await this.inventoryEditorRepository.save(inventory);

      return movement;

    } catch (error) {
      this.logger.error('Error al crear movimiento:', error);
      throw new BadRequestException('Error al crear movimiento de inventario');
    }
  }

  //! Función para importación masiva desde CSV/Excel
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

  //! funcion para consultar movimientos de inventario (READER - SELECT)
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
  
  //* ---------- FUNCIONES PARA ATRIBUTOS
  //! funcion para consultar todas los atributos (READER - SELECT)
  getAttributes(): Promise<Attribute[]> {
    return this.attributeReaderRepository.find();
  }

  //* ---------- FUNCIONES PARA MARCAS
  //! funcion para registrar una variante de producto (EDITOR - CREATE)
  async createMarca(dto: CreateMarcaDto): Promise<Marca> {
    // READER para verificar duplicado
    const marca = await this.marcaReaderRepository.findOneBy({
      nombre: dto.nombre,
    });

    if (marca) {  throw new BadRequestException('La marca ya existe'); }

    const variant = this.marcaEditorRepository.create({
      nombre: dto.nombre,
      imagen: dto.imagen,
    });

    return await this.marcaEditorRepository.save(variant);
  }

  //! funcion para actualizar una marca (EDITOR - UPDATE)
  async updateMarca( dto: UpdateMarcaDto ): Promise<Marca> {
    // READER para verificar existencia
    const marca = await this.marcaReaderRepository.findOne({
      where: { id_marca: dto.id_marca },
    });

    if (!marca) {  throw new BadRequestException('La marca no existe'); }

    // Si se está cambiando el nombre, validar duplicado (READER)
    if (dto.nombre && dto.nombre !== marca.nombre) {
      const existe = await this.marcaReaderRepository.findOneBy({
        nombre: dto.nombre,
      });

      if (existe) { throw new BadRequestException('Ya existe una marca con ese nombre'); }
    }

    this.marcaEditorRepository.merge(marca, dto);

    return await this.marcaEditorRepository.save(marca); // EDITOR para UPDATE
  }

  //! funcion para consultar todas las marcas (READER - SELECT)
  async getMarcas(): Promise<Marca[]> {
    return await this.marcaReaderRepository.find({
      order: { nombre: 'ASC' }
    });
  }
  //* ---------- FUNCIONES PARA CATEGORIAS
  //! funcion para registrar una variante de producto (EDITOR - CREATE)
  async createCategory(dto: CreateCategorieDto): Promise<Category> {
    // READER para verificar duplicado
    const category = await this.categoryReaderRepository.findOneBy({
      nombre: dto.nombre,
    });

    if (category) {
      throw new BadRequestException('La categoría ya existe');
    }

    const variant = this.categoryEditorRepository.create({
      nombre: dto.nombre,     
      id_padre: dto.id_padre, 
    });

    return await this.categoryEditorRepository.save(variant);
  }

//! funcion para actualizar una categoria (EDITOR - UPDATE)
async updateCategory(dto: UpdateCategorieDto): Promise<Category> {
  // READER para verificar existencia
  const category = await this.categoryReaderRepository.findOne({
    where: { id_categoria: dto.id_categoria },
  });

  if (!category) {
    throw new BadRequestException('La categoría no existe');
  }
  
  // READER para verificar nombre duplicado EXCLUYENDO la categoría actual
  const categoryName = await this.categoryReaderRepository.findOne({
    where: {
      nombre: dto.nombre,
      id_categoria: Not(dto.id_categoria)
    }
  });
  
  if (categoryName) {
    throw new BadRequestException('Ya existe una categoría con ese nombre');
  }

  this.categoryEditorRepository.merge(category, dto);

  return await this.categoryEditorRepository.save(category);
}

  //! funcion para consultar todas las categorias (READER - SELECT)
  async getCategories(): Promise<Category[]> {
    return await this.categoryReaderRepository.find();
  }

  //! funcion para traer las ordenes de los usuarios, por parte del empleado (READER - SELECT)
  async getOrderss(): Promise<Orders[]> {
    return await this.ordersReaderRepository.find();
  }

  //* PARA EL MENU
  async getCategoriesByParent(parentId: number): Promise<Category[]> {
    return await this.categoryReaderRepository.find({
      where: { id_padre: parentId },
      order: { nombre: 'ASC' }
    });
  }

  // Obtener deportes (atributos con id_padre = 40)
  async getSports(): Promise<Sports[]> {
    return await this.sportReaderRepository.find({
      order: { nombre: 'ASC' }
    });
  }

  // Obtener menú completo
  async getCompleteMenu(): Promise<any> {
    const [sports, clothing, accessories, brands] = await Promise.all([
      this.getSports(),
      this.getCategoriesByParent(1),      // Ropa (id_padre = 1)
      this.getCategoriesByParent(34),     // Accesorios (id_padre = 34)
      this.getMarcas()
    ]);

    return {
      sports,
      clothing,
      accessories,
      brands
    };
  }
}
