/* eslint-disable */
import { Injectable, BadRequestException } from '@nestjs/common';
import { CreateProductDto } from './dto/create-product.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Product } from './entities/product.entity';
import { Repository } from 'typeorm';

@Injectable()
export class ProductsService {
  constructor(
    @InjectRepository(Product)
    private readonly productRepository: Repository<Product>,
  ) {}

  //! funcion para registrar un producto
  async createProduct(createProductDto: CreateProductDto): Promise<Product> {
    try {
      const product = this.productRepository.create({
        ...createProductDto,
        imagenes: createProductDto.imagenes || [], 
        activo: 0,
        precio: 0.0,
        fecha_creacion: new Date(),
        fecha_actualizacion: new Date(),
      });

      return await this.productRepository.save(product);
    } catch (error) {
      if (error.code === '23503') { // Foreign key violation
        throw new BadRequestException('Categoría o marca no válida');
      }
      console.error('Error al crear producto:', error);
      throw new BadRequestException('Error al crear el producto');
    }
  }
  //! funcion para consultar todos los productos
  async getAllProducts(): Promise<Product[]> {
    try {
      return this.productRepository.find(); 
    } catch (error) {
      throw new BadRequestException('Error al obtener los productos');
    }
  }

}
