/* eslint-disable */
import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository, InjectDataSource } from '@nestjs/typeorm';
import { Repository, DataSource, Not } from 'typeorm';

import { CreateProductDto } from './dto/product/create-product.dto';
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

import { CreateMarcaDto } from './dto/marca/create-marca.tdo';
import { UpdateMarcaDto } from './dto/marca/update-marca.dto';
import { Marca } from './entities/marca/marca.entity';

import { CreateCategorieDto } from './dto/categories/create-categorie.dto';
import { UpdateCategorieDto } from './dto/categories/update-categorie.dto';
import { Category } from './entities/categorie/categorie.entity';

import { Orders } from './entities/orders/orders.entity';

import { CreateInventoryMovementDto } from './dto/inventory/create-inventory_movement.dto';
import { InventoryMovements } from './entities/inventory/inventory_movements.entity';
import { Inventory } from './entities/inventory/inventory.entity';

@Injectable()
export class ProductsService {
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
      console.error('Error al crear producto:', error);
      throw new BadRequestException('Error al crear el producto', error);
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
      console.log(error);
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
      console.error('ERROR REAL:', error);
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
      console.error('ERROR REAL:', error);
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
      console.error('ERROR REAL:', error);
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
      console.error('ERROR REAL:', error);
      throw error;
    }
  }

  //! funcion para consultar todos los productos (READER - SELECT)
  async getInventoryProducts(): Promise<any[]> {
    try {
      const result = await this.productReaderRepository.query(
        `SELECT * FROM core.get_inventory_products();`
      );
      return result;
    } catch (error) {
      console.error('ERROR REAL:', error);
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
  async createInventoryMovement(
    createInventoryMovementDto: CreateInventoryMovementDto,
  ): Promise<InventoryMovements> {
    try {
      // READER para verificar existencia
      const inventory = await this.inventoryReaderRepository.findOne({
        where: { id_variante: createInventoryMovementDto.id_variante },
      });

      if (!inventory) {
        throw new BadRequestException('Inventario no encontrado');
      }

      // EDITOR para crear movimiento
      const movement = this.inventoryMovementsEditorRepository.create({
        ...createInventoryMovementDto,
      });

      await this.inventoryMovementsEditorRepository.save(movement);

      // EDITOR para actualizar stock
      inventory.stock_actual += createInventoryMovementDto.cantidad;
      await this.inventoryEditorRepository.save(inventory);

      return movement;

    } catch (error) {
      console.error('Error al crear movimiento de inventario:', error);
      throw new BadRequestException('Error al crear movimiento de inventario', error);
    }
  }

  //! funcion para consultar movimientos de inventario (READER - SELECT)
  async getInventoryMovements(): Promise<InventoryMovements[]> {
    try {
      const movements = await this.inventoryMovementsReaderRepository.find({
        order: { fecha: 'DESC' },
      });

      return movements;
    } catch (error) {
      console.error('Error al obtener movimientos de inventario:', error);
      throw new BadRequestException(
        'Error al obtener movimientos de inventario',
        error,
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
    return await this.marcaReaderRepository.find();
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
    
    // READER para verificar nombre duplicado
    const categoryName = await this.categoryReaderRepository.findOneBy({
      nombre: dto.nombre,
    });
    if(categoryName) {
      throw new BadRequestException('Ya existe una categoría con ese nombre');
    }

    this.categoryEditorRepository.merge(category, dto);

    return await this.categoryEditorRepository.save(category); // EDITOR para UPDATE
  }

  //! funcion para consultar todas las categorias (READER - SELECT)
  async getCategories(): Promise<Category[]> {
    return await this.categoryReaderRepository.find();
  }

  //! funcion para traer las ordenes de los usuarios, por parte del empleado (READER - SELECT)
  async getOrderss(): Promise<Orders[]> {
    return await this.ordersReaderRepository.find();
  }
}