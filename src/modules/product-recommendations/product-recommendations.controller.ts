import { Controller, Get, Param, ParseIntPipe, Query } from '@nestjs/common';
import { ProductRecommendationsService } from './product-recommendations.service';

@Controller('products/recommendations')
export class ProductRecommendationsController {
  constructor(
    private readonly productRecommendationsService: ProductRecommendationsService,
  ) {}

  @Get(':productId')
  getRecommendations(
    @Param('productId', ParseIntPipe) productId: number,
    @Query('limit') limit?: string,
  ) {
    const parsedLimit = Math.min(Math.max(Number(limit) || 10, 1), 10);
    return this.productRecommendationsService.getRecommendations(
      productId,
      parsedLimit,
    );
  }
}
