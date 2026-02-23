/* eslint-disable */
import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource  } from 'typeorm';

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

@Injectable()
export class ProductsService {
  constructor(
    private readonly dataSource: DataSource,
    //productos
    @InjectRepository(Product)
    private readonly productRepository: Repository<Product>,
    @InjectRepository(ProductVariant)
    private readonly productVariantRepository: Repository<ProductVariant>,
    @InjectRepository(VariantAttributeValue)
    private readonly variantAttributeValueRepository: Repository<VariantAttributeValue>,
    @InjectRepository(Attribute)
    private readonly attributeRepository: Repository<Attribute>,
    //marcas
    @InjectRepository(Marca)
    private readonly marcaRepository: Repository<Marca>,
    //categorias
    @InjectRepository(Category)
    private readonly categoryRepository: Repository<Category>,
  ) {}

  //* ---------- FUNCIONES PARA PRODUCTOS
  //! funcion para registrar un producto
  async createProduct(createProductDto: CreateProductDto): Promise<Product> {
    try {
      const product = this.productRepository.create({
        nombre: createProductDto.nombre,
        descripcion: createProductDto.descripcion,
        id_marca: createProductDto.id_marca,
        id_categoria: createProductDto.id_categoria,
        activo: false,
      });

      return await this.productRepository.save(product);
    } catch (error) {
      console.error('Error al crear producto:', error);
      throw new BadRequestException('Error al crear el producto', error);
    }
  }

  //! funcion para registrar una variante de producto
  async createProductVariant(dto: CreateProductVariantDto): Promise<ProductVariant> {
    const product = await this.productRepository.findOneBy({
      id_producto: dto.id_producto,
    });

    if (!product) {
      throw new BadRequestException('El producto no existe');
    }

    const variant = this.productVariantRepository.create({
      id_producto: dto.id_producto,
      sku: dto.sku,
      precio: dto.precio,
      stock: dto.stock,
      imagenes: dto.imagenes ?? [],
    });

    return await this.productVariantRepository.save(variant);
  }

  //! funcion para registrar un atributo de producto
  async createAttribute(dto: CreateAttributeDto): Promise<Attribute> {
    const attribute = await this.attributeRepository.findOneBy({
      nombre: dto.nombre,
    });

    if (attribute) {
      throw new BadRequestException('El atributo ya existe');
    }

    const variant = this.attributeRepository.create({
      nombre: dto.nombre,      
    });

    return await this.attributeRepository.save(variant);
  }

  //! funcion para registrar los valores de los atributos de una variante
  async createVariantAttributeValue(dto: CreateVarAttributeValuesDto): Promise<VariantAttributeValue> {
    try {
      const atributo = await this.variantAttributeValueRepository.findOneBy({
        id_atributo: dto.id_atributo,
      });
      if (!atributo) {
        throw new BadRequestException('El atributo no existe');
      }
      const attribute = this.variantAttributeValueRepository.create({
        id_variante: dto.id_variante,
        id_atributo: dto.id_atributo,
        valor: dto.valor,
      });

      return await this.variantAttributeValueRepository.save(attribute);
    } catch (error) {
      console.log(error);
      throw new BadRequestException('Error al crear atributo de variante');
    }
  }

  //! funcion para consultar todos los productos
  async getAllProducts(): Promise<any[]> {
    try {
      const result = await this.productRepository.query(
        `SELECT * FROM get_all_products();`
      );
      return result;
    } catch (error) {
      console.error('ERROR REAL:', error);
      throw error;
    }
  }

  //! funcion para consultar todos los productos recientemente creados
  async getRecientProducts(): Promise<any[]> {
    try {
      const result = await this.productRepository.query(
        `SELECT * FROM get_recients_products();`
      );
      return result;
    } catch (error) {
      console.error('ERROR REAL:', error);
      throw error;
    }
  }

  //! funcion para consultar productos variantes pero con atributos vacios
  async getProductsWithoutVariantsAttributes(): Promise<any[]> {
    try {
      const result = await this.productRepository.query(
        `SELECT * FROM get_products_with_variants_without_attributes();`
      );
      return result;
    } catch (error) {
      console.error('ERROR REAL:', error);
      throw error;
    }
  }

  //! funcion para consultar las variantes de un producto
  async getVariantsByProduct(id: number): Promise<ProductVariant[]> {
    return await this.productVariantRepository.find({
      where: { id_producto: id },
    });
  }

  //! funcion para consultar todos los productos
  async getProductDetail(id: number): Promise<any[]> {
    try {
      const result = await this.productRepository.query(
        `SELECT * FROM get_all_products() where id_producto = ${id};`
      );
      return result;
    } catch (error) {
      console.error('ERROR REAL:', error);
      throw error;
    }
  }

  //! funcion para consultar todos los productos
  async getInventoryProducts(): Promise<any[]> {
    try {
      const result = await this.productRepository.query(
        `SELECT * FROM get_inventory_products();`
      );
      return result;
    } catch (error) {
      console.error('ERROR REAL:', error);
      throw error;
    }
  }

  //! funcion para actualizar un producto
  async updateProductInv(dto: { id_producto: number, estado: boolean }): Promise<number> {
    try {
      const product = await this.productRepository.findOne({
        where: { id_producto: dto.id_producto }
      });

      if (!product) {
        throw new BadRequestException('Producto no encontrado');
      }

      product.activo = dto.estado;
      
      await this.productRepository.save(product);

      return 1;
    } catch (error) {
      throw error;
    }
  }

  //! funcion para actualizar datos generales de producto
  async updateProductFull(dto: UpdateProductFullDto): Promise<UpdateProductResult> {
    const result: UpdateProductResult[] = await this.dataSource.query(
      `
      SELECT * FROM update_full_product(
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

  //! Funcion para actualizar datos de producto: variante y atributos
  async updateProductVarAttr(dto: UpdateProductVariantAttributeDto): Promise<UpdateProductVarAttResult> {
    const result: UpdateProductVarAttResult[] = await this.dataSource.query(
      `
      SELECT * FROM update_product_var_attr(
        $1,
        $2, $3, $4, $5, $6
      )
      `,
      [
        dto.id_producto,

        dto.id_variante,
        dto.sku,
        JSON.stringify(dto.imagenes),
        dto.stock,
        dto.precio,
      ]
    );

    return result[0];
  }
  
  //* ---------- FUNCIONES PARA ATRIBUTOS
  //! funcion para consultar todas los atributos
  async getAttributes(): Promise<Attribute[]> {
    return this.attributeRepository.find();
  }


  //* ---------- FUNCIONES PARA MARCAS
  //! funcion para registrar una variante de producto
  async createMarca(dto: CreateMarcaDto): Promise<Marca> {
    const marca = await this.marcaRepository.findOneBy({
      nombre: dto.nombre,
    });

    if (marca) {  throw new BadRequestException('La marca ya existe'); }

    const variant = this.marcaRepository.create({
      nombre: dto.nombre,
      sitio_web: dto.sitio_web,
    });

    return await this.marcaRepository.save(variant);
  }

  //! funcion para actualizar una marca
  async updateMarca( dto: UpdateMarcaDto ): Promise<Marca> {
    const marca = await this.marcaRepository.findOne({
      where: { id_marca: dto.id_marca },
    });

    if (!marca) {  throw new BadRequestException('La marca no existe'); }

    // Si se está cambiando el nombre, validar duplicado
    if (dto.nombre && dto.nombre !== marca.nombre) {
      const existe = await this.marcaRepository.findOneBy({
        nombre: dto.nombre,
      });

      if (existe) { throw new BadRequestException('Ya existe una marca con ese nombre'); }
    }

    this.marcaRepository.merge(marca, dto);

    return await this.marcaRepository.save(marca);
  }

   //! funcion para consultar todas las marcas
  async getMarcas(): Promise<Marca[]> {
    return await this.marcaRepository.find();
  }

  //* ---------- FUNCIONES PARA CATEGORIAS
  //! funcion para registrar una variante de producto
  async createCategory(dto: CreateCategorieDto): Promise<Category> {
    const category = await this.categoryRepository.findOneBy({
      nombre: dto.nombre,
    });

    if (category) {
      throw new BadRequestException('La categoría ya existe');
    }

    const variant = this.categoryRepository.create({
      nombre: dto.nombre,     
      id_padre: dto.id_padre, 
    });

    return await this.categoryRepository.save(variant);
  }

  //! funcion para actualizar una categoria
  async updateCategory(dto: UpdateCategorieDto): Promise<Category> {
    const category = await this.categoryRepository.findOne({
      where: { id_categoria: dto.id_categoria },
    });

    if (!category) {
      throw new BadRequestException('La categoría no existe');
    }

    this.categoryRepository.merge(category, dto);

    return await this.categoryRepository.save(category);
  }

  //! funcion para consultar todas las categorias
  async getCategories(): Promise<Category[]> {
    return await this.categoryRepository.find();
  }


}
