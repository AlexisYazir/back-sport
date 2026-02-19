import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Product } from './entities/product.entity';
import { ProductVariant } from './entities/product_variant.entity';
import { ProductsController } from './products.controller';
import { ProductsService } from './products.service';
import { VariantAttributeValue } from './entities/variant_attr_vals.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([Product, ProductVariant, VariantAttributeValue]),
  ],
  controllers: [ProductsController],
  providers: [ProductsService],
  exports: [ProductsService],
})
export class ProductsModule {}
