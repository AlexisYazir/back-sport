/* eslint-disable */
import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, Not, Repository } from 'typeorm';

import { CreateAttributeDto } from '../dto/product/create-attribute.dto';
import { CreateProductDto } from '../dto/product/create-product.dto';
import { CreateProductSportsDto } from '../dto/product/create-product-sports.dto';
import { CreateProductVariantDto } from '../dto/product/create-product_variant.dto';
import { CreateVarAttributeValuesDto } from '../dto/product/create-var-att_vls.dto';
import {
  UpdateProductFullDto,
  UpdateProductResult,
} from '../dto/product/update-product-full.dto';
import {
  UpdateProductVariantAttributeDto,
  UpdateProductVarAttResult,
} from '../dto/product/update.product-var-attr.dto';
import { Attribute } from '../entities/product/atributtes.entity';
import { Product } from '../entities/product/product.entity';
import { ProductVariant } from '../entities/product/product_variant.entity';
import { VariantAttributeValue } from '../entities/product/variant_attr_vals.entity';
import { Sports } from '../entities/sports/sport.entity';
import {
  CloudinaryService,
  CloudinaryUploadResult,
} from './cloudinary.service';

@Injectable()
export class ProductCatalogService {
  private readonly logger = new Logger(ProductCatalogService.name);

  constructor(
    @InjectDataSource('editorConnection')
    private readonly editorDataSource: DataSource,

    @InjectRepository(Product, 'editorConnection')
    private readonly productEditorRepository: Repository<Product>,
    @InjectRepository(ProductVariant, 'editorConnection')
    private readonly productVariantEditorRepository: Repository<ProductVariant>,
    @InjectRepository(VariantAttributeValue, 'editorConnection')
    private readonly variantAttributeValueEditorRepository: Repository<VariantAttributeValue>,
    @InjectRepository(Attribute, 'editorConnection')
    private readonly attributeEditorRepository: Repository<Attribute>,

    @InjectRepository(Product, 'readerConnection')
    private readonly productReaderRepository: Repository<Product>,
    @InjectRepository(ProductVariant, 'readerConnection')
    private readonly productVariantReaderRepository: Repository<ProductVariant>,
    @InjectRepository(Attribute, 'readerConnection')
    private readonly attributeReaderRepository: Repository<Attribute>,
    @InjectRepository(Sports, 'readerConnection')
    private readonly sportReaderRepository: Repository<Sports>,

    private readonly cloudinaryService: CloudinaryService,
  ) {}

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
        new Set(
          (dto.ids_deportes ?? [])
            .map(Number)
            .filter((id) => Number.isInteger(id) && id > 0),
        ),
      );

      if (sportIds.length > 0) {
        const existingSports = await this.sportReaderRepository.query(
          `SELECT id_deporte FROM core.deportes WHERE id_deporte = ANY($1::int[])`,
          [sportIds],
        );

        if (existingSports.length !== sportIds.length) {
          throw new BadRequestException(
            'Uno o mas deportes seleccionados no existen',
          );
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

  async createProductVariant(
    dto: CreateProductVariantDto,
  ): Promise<ProductVariant> {
    const product = await this.productReaderRepository.findOneBy({
      id_producto: dto.id_producto,
    });

    const variante = await this.productVariantReaderRepository.findOneBy({
      sku: dto.sku,
    });

    if (variante) {
      throw new BadRequestException('EL codigo ya existe');
    }

    if (!product) {
      throw new BadRequestException('El producto no existe');
    }

    const variant = this.productVariantEditorRepository.create({
      id_producto: dto.id_producto,
      sku: dto.sku,
      precio: dto.precio,
      imagenes: dto.imagenes ?? [],
      atributos: dto.atributos ?? {},
    });

    return await this.productVariantEditorRepository.save(variant);
  }

  async createAttribute(dto: CreateAttributeDto): Promise<Attribute> {
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

  async createVariantAttributeValue(
    dto: CreateVarAttributeValuesDto,
  ): Promise<VariantAttributeValue> {
    try {
      const attribute = this.variantAttributeValueEditorRepository.create({
        id_variante: dto.id_variante,
        id_atributo: dto.id_atributo,
        valor: dto.valor,
      });

      return await this.variantAttributeValueEditorRepository.save(attribute);
    } catch (error) {
      this.logger.error('Error al crear atributo de variante: ', error);
      throw new BadRequestException('Error al crear atributo de variante');
    }
  }

  async getAllProducts(): Promise<any[]> {
    try {
      const result = await this.productReaderRepository.query(
        `
        SELECT
          p.id_producto,
          p.nombre AS producto,
          p.descripcion,
          p.activo,
          p.fecha_creacion,
          m.nombre AS marca,
          m.imagen AS imagen_marca,
          c.nombre AS categoria,
          cp.nombre AS categoria_padre,
          COALESCE(d.deportes, '[]'::jsonb) AS deportes,
          COALESCE(
            jsonb_agg(
              DISTINCT jsonb_build_object(
                'id_variante', v.id_variante,
                'sku', v.sku,
                'precio', v.precio,
                'stock', vi.stock_actual,
                'imagenes', v.imagenes,
                'atributos',
                  (
                    SELECT jsonb_object_agg(a.nombre, vav.valor)
                    FROM core.variant_attribute_values vav
                    JOIN core.attributes a
                      ON a.id_atributo = vav.id_atributo
                    WHERE vav.id_variante = v.id_variante
                  )
              )
            ) FILTER (WHERE v.id_variante IS NOT NULL),
            '[]'::jsonb
          ) AS variantes
        FROM core.products p
        LEFT JOIN core.marcas m
          ON m.id_marca = p.id_marca
        LEFT JOIN core.categories c
          ON c.id_categoria = p.id_categoria
        LEFT JOIN core.categories cp
          ON cp.id_categoria = c.id_padre
        LEFT JOIN core.product_variants v
          ON v.id_producto = p.id_producto
        INNER JOIN core.inventory vi
    	ON vi.id_variante = v.id_variante
      AND vi.stock_actual > 0
        LEFT JOIN (
          SELECT
            pd.id_producto,
            jsonb_agg(DISTINCT d.nombre ORDER BY d.nombre) AS deportes
          FROM core.product_deportes pd
          JOIN core.deportes d
            ON d.id_deporte = pd.id_deporte
          GROUP BY pd.id_producto
        ) d
          ON d.id_producto = p.id_producto
        WHERE p.activo = TRUE
        GROUP BY
          p.id_producto,
          p.nombre,
          p.descripcion,
          p.activo,
          p.fecha_creacion,
          m.nombre,
          m.imagen,
          c.nombre,
          cp.nombre,
          d.deportes
        ORDER BY p.fecha_creacion DESC;
        `,
      );
      return result;
    } catch (error) {
      this.logger.error('Error al cargar todos los productos: ', error);
      throw error;
    }
  }

  async getRecientProducts(): Promise<any[]> {
    try {
      const result = await this.productReaderRepository.query(
        `SELECT * FROM core.get_recients_products();`,
      );
      return result;
    } catch (error) {
      this.logger.error('ERROR REAL:', error);
      throw error;
    }
  }

  async getProductsWithoutVariantsAttributes(): Promise<any[]> {
    try {
      const result = await this.productReaderRepository.query(
        `SELECT * FROM core.get_products_with_variants_without_attributes();`,
      );
      return result;
    } catch (error) {
      this.logger.error('Error al consultar productos variantes:', error);
      throw error;
    }
  }

  async getVariantsByProduct(id: number): Promise<any[]> {
    try {
      const variants = await this.productVariantReaderRepository.query(
        `SELECT * FROM core.get_variants_product_by_id($1)`,
        [id],
      );

      return variants;
    } catch (error) {
      this.logger.error('Error al consultar variantes de producto por id: ', error);
      throw new Error('Error fetching product variants');
    }
  }

  async getProductDetail(id: number): Promise<any[]> {
    try {
      const result = await this.productReaderRepository.query(
        `
        SELECT
          p.id_producto,
          p.nombre AS producto,
          p.descripcion,
          p.activo,
          p.fecha_creacion,
          m.nombre AS marca,
          m.imagen AS imagen_marca,
          c.nombre AS categoria,
          cp.nombre AS categoria_padre,
          COALESCE(d.deportes, '[]'::jsonb) AS deportes,
          COALESCE(
            jsonb_agg(
              DISTINCT jsonb_build_object(
                'id_variante', v.id_variante,
                'sku', v.sku,
                'precio', v.precio,
                'stock', COALESCE(vi.stock_actual, 0),
                'imagenes', v.imagenes,
                'atributos',
                  (
                    SELECT jsonb_object_agg(a.nombre, vav.valor)
                    FROM core.variant_attribute_values vav
                    JOIN core.attributes a
                      ON a.id_atributo = vav.id_atributo
                    WHERE vav.id_variante = v.id_variante
                  )
              )
            ) FILTER (WHERE v.id_variante IS NOT NULL),
            '[]'::jsonb
          ) AS variantes
        FROM core.products p
        LEFT JOIN core.marcas m
          ON m.id_marca = p.id_marca
        LEFT JOIN core.categories c
          ON c.id_categoria = p.id_categoria
        LEFT JOIN core.categories cp
          ON cp.id_categoria = c.id_padre
        INNER JOIN core.product_variants v
          ON v.id_producto = p.id_producto
        INNER JOIN core.inventory vi
          ON vi.id_variante = v.id_variante
          AND vi.stock_actual > 0
        LEFT JOIN (
          SELECT
            pd.id_producto,
            jsonb_agg(DISTINCT d.nombre ORDER BY d.nombre) AS deportes
          FROM core.product_deportes pd
          JOIN core.deportes d
            ON d.id_deporte = pd.id_deporte
          GROUP BY pd.id_producto
        ) d
          ON d.id_producto = p.id_producto
        WHERE p.id_producto = $1
          AND p.activo = TRUE
        GROUP BY
          p.id_producto,
          p.nombre,
          p.descripcion,
          p.activo,
          p.fecha_creacion,
          m.nombre,
          m.imagen,
          c.nombre,
          cp.nombre,
          d.deportes
        `,
        [id],
      );
      return result;
    } catch (error) {
      this.logger.error('Error al cargar los detalles de un producto: ', error);
      throw error;
    }
  }

  async updateProductFull(
    dto: UpdateProductFullDto,
  ): Promise<UpdateProductResult> {
    const result: UpdateProductResult[] =
      await this.productEditorRepository.query(
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
        ],
      );

    return result[0];
  }

  async updateProductVariant(
    dto: UpdateProductVariantAttributeDto,
  ): Promise<UpdateProductVarAttResult> {
    const existingVariant = await this.productVariantReaderRepository.findOne({
      where: {
        sku: dto.sku,
        id_variante: Not(dto.id_variante),
      },
    });

    if (existingVariant) {
      throw new BadRequestException(
        'El SKU(Codigo) ya está en uso por otra variante',
      );
    }

    const result: UpdateProductVarAttResult[] =
      await this.productVariantEditorRepository.query(
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
          JSON.stringify(dto.atributos),
        ],
      );

    return result[0];
  }

  getAttributes(): Promise<Attribute[]> {
    return this.attributeReaderRepository.find();
  }
}
