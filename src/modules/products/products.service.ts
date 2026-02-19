/* eslint-disable */
import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { CreateProductDto } from './dto/create-product.dto';
import { Product } from './entities/product.entity';

import { CreateProductVariantDto } from './dto/create-product_variant.dto';
import { ProductVariant } from './entities/product_variant.entity';

import { CreateVarAttributeValuesDto } from './dto/create-var-att_vls.dto';
import { VariantAttributeValue } from './entities/variant_attr_vals.entity';

@Injectable()
export class ProductsService {
  constructor(
    @InjectRepository(Product)
    private readonly productRepository: Repository<Product>,
    @InjectRepository(ProductVariant)
    private readonly productVariantRepository: Repository<ProductVariant>,
    @InjectRepository(VariantAttributeValue)
    private readonly variantAttributeValueRepository: Repository<VariantAttributeValue>,
  ) {}

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
      throw new BadRequestException('Error al crear el producto');
    }
  }

  //! funcion para registrar una variante de producto
  async createProductVariant(
    dto: CreateProductVariantDto,
  ): Promise<ProductVariant> {
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

  async createVariantAttributeValue(
    dto: CreateVarAttributeValuesDto,
  ): Promise<VariantAttributeValue> {
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
        `SELECT * FROM get_all_products();`,
      );

      return result;
    } catch (error) {
      console.log(error);
      throw new BadRequestException('Error al obtener los productos');
    }
  }
}
