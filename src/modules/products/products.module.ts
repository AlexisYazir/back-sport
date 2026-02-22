import { ProductsController } from './products.controller';
import { ProductsService } from './products.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Module } from '@nestjs/common';

import { VariantAttributeValue } from './entities/product/variant_attr_vals.entity';
import { ProductVariant } from './entities/product/product_variant.entity';
import { Product } from './entities/product/product.entity';
import { Attribute } from './entities/product/atributtes.entity';
import { Marca } from './entities/marca/marca.entity';
import { Category } from './entities/categorie/categorie.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      Product,
      ProductVariant,
      VariantAttributeValue,
      Attribute,
      Marca,
      Category,
    ]),
  ],
  controllers: [ProductsController],
  providers: [ProductsService],
  exports: [ProductsService],
})
export class ProductsModule {}
