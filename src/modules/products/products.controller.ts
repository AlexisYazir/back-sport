import { Controller, Post, Body, Get } from '@nestjs/common';
import { ProductsService } from './products.service';
import { CreateProductDto } from './dto/create-product.dto';
// import { CreateAttributeDto } from './dto/create-attribute.dto';
import { CreateVarAttributeValuesDto } from './dto/create-var-att_vls.dto';
import { CreateProductVariantDto } from './dto/create-product_variant.dto';

@Controller('products')
export class ProductsController {
  constructor(private readonly productsService: ProductsService) {}

  @Post('create-product')
  async createProduct(@Body() createProductDto: CreateProductDto) {
    return this.productsService.createProduct(createProductDto);
  }

  @Post('create-product-variant')
  async createProductVariant(
    @Body() createProductVariantDto: CreateProductVariantDto,
  ) {
    return this.productsService.createProductVariant(createProductVariantDto);
  }

  @Post('create-variant-attribute-values')
  async createVariantAttributeValue(
    @Body() createVarAttributeValuesDto: CreateVarAttributeValuesDto,
  ) {
    return this.productsService.createVariantAttributeValue(
      createVarAttributeValuesDto,
    );
  }

  @Get('get-all-products')
  async getAllProducts() {
    return this.productsService.getAllProducts();
  }
}
